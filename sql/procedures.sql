BEGIN TRANSACTION;

	/* BigRandom()	Generates a random number with BIGINT boundaries.
	 *
	 * Returns: A BIGINT random number.
	 */
	CREATE OR REPLACE FUNCTION BigRandom() RETURNS BIGINT AS $$
	DECLARE
		left_half INTEGER;
		right_half INTEGER;
	BEGIN
		left_half := trunc(random() * 2147483647 + round(random()));
		right_half := trunc(random() * 2147483647 + round(random()));
		return ((left_half::BIGINT << 32) + right_half);
	END;
	$$ LANGUAGE plpgsql;

	/* CreateAccount()	Creates a new account.
	 *
	 * Returns: 0 on success, 3 if the e-mail already exists, 2 otherwise.
	 */
	CREATE OR REPLACE FUNCTION PasteBin.CreateAccount(AEMail VARCHAR(256), ADisplayName VARCHAR(256), APassword VARCHAR(72)) RETURNS INT AS $$
	BEGIN
		INSERT INTO PasteBin.Users (DisplayName, EMail, Password) VALUES (ADisplayName, AEMail, crypt(APassword, gen_salt('bf', 12)));
		RETURN 0;
	EXCEPTION 
		WHEN unique_violation THEN
			IF EXISTS (SELECT 1 FROM PasteBin.Users WHERE EMail = AEMail) THEN
				RETURN 3;
			ELSE 
				RETURN 2;
			END IF;
 		WHEN OTHERS THEN
 			RETURN 2;
	END;
	$$ LANGUAGE plpgsql;

	/* InsertToken()	Creates a new Series + Token pair, or updates an existing Series record with a new token.
	 * 
	 * Returns: Either a 1-column record (on failure), or 3-column record (on success).
	 * 	1-column-record: Contains a non-zero INTEGER value indicating the error that occurred:
	 *	                 - If (1) = User does not exist.
	 *	                 - If (2) = An exception has occurred.
	 *	3-column-record: - First column is an INTEGER with value 0, indicating that the function was successful.
	 *	                 - Second column is the SERIESID (be aware that this could be different from the provided
	 *                       argument. If the provided ASeriesID does not exist, it will generate a new one).
	 *	                 - Third column is the new TOKEN value.
	 */
	CREATE OR REPLACE FUNCTION PasteBin.InsertToken(AUserID INTEGER, ASeriesID BIGINT DEFAULT NULL,
	                                                OUT Result INT, OUT OSeriesID BIGINT, OUT OToken VARCHAR(64)) RETURNS RECORD AS $$
	DECLARE
		VSeriesID BIGINT;
		VToken VARCHAR(64);
		VExists BOOLEAN;
	BEGIN
		IF EXISTS (SELECT 1 FROM PasteBin.Users WHERE UserID = AUserID) THEN
			VExists := FALSE;
			IF (ASeriesID IS NOT NULL) THEN
				IF EXISTS (SELECT 1 FROM PasteBin.Tokens WHERE UserID = AUserID AND SeriesID = ASeriesID) THEN
					VSeriesID := ASeriesID;
					VExists := TRUE;
				ELSE
					VSeriesID := BigRandom();
				END IF;
			ELSE
				VSeriesID := BigRandom();
			END IF;
			
			VToken := substr(encode(gen_random_bytes(48), 'base64'), 0, 65);

			IF (VExists) THEN
				UPDATE PasteBin.Tokens SET Token = VToken WHERE UserID = AUserID AND SeriesID = ASeriesID;
			ELSE 
				INSERT INTO PasteBin.Tokens (UserID, SeriesID, Token) VALUES (AUserID, VSeriesID, VToken);
			END IF;

			Result := 0;
			OSeriesID := VSeriesID;
			OToken := VToken;
		ELSE
			Result := 1;
		END IF;
	EXCEPTION
		WHEN OTHERS THEN
			Result := 2;	-- An exception has occurred.
	END;
	$$ LANGUAGE plpgsql;

	/* ValidateToken()	Validates a UserID + SeriesID + Token combination. If successful, it will create a new 
	 *			token.
	 *
	 * Returns: Same record/values from InsertToken(), in addition to the following:
	 *	(3) - Correct UserID + SeriesID pair, but invalid TokenID. Will result in all records with the same 
	 *	      UserID + SeriesID to be deleted (basically, "someone" is using an old cookie that they shouldn't
	 *	      be using).
	 *	(4) - Invalid SeriesID (but correct UserID).
	 */
	CREATE OR REPLACE FUNCTION PasteBin.ValidateToken(AUserID INTEGER, ASeriesID BIGINT, AToken VARCHAR(64), 
	                                                  OUT Result INT, OUT OSeriesID BIGINT, OUT OToken VARCHAR(64)) RETURNS RECORD AS $$
	DECLARE
		VToken VARCHAR(64);
	BEGIN
		SELECT Token INTO VToken FROM PasteBin.Tokens WHERE UserID = AUserID AND SeriesID = ASeriesID LIMIT 1;
		
		IF (VToken IS NOT NULL) THEN
			IF (AToken = VToken) THEN
				SELECT qry.Result, qry.OSeriesID, qry.OToken INTO Result, OSeriesID, OToken FROM PasteBin.InsertToken(AUserID, ASeriesID) qry;
			ELSE
				DELETE FROM PasteBin.Tokens WHERE UserID = AUserID AND SeriesID = ASeriesID;
				Result := 3;
			END IF;
		ELSE
			IF EXISTS (SELECT 1 FROM PasteBin.Tokens WHERE UserID = AUserID) THEN
				Result := 4;
			ELSE
				Result := 1;
			END IF;
		END IF;
	EXCEPTION
		WHEN OTHERS THEN
			Result := 2;	-- An exception has occurred.
	END;
	$$ LANGUAGE plpgsql;

	/* AddUserIP()	Associate the given IP address with a user.
	 *
	 * Returns: N/A
	 */
	CREATE OR REPLACE FUNCTION PasteBin.AddUserIP(AUserID INTEGER, AIPAddr INET) RETURNS VOID AS $$
	BEGIN
		INSERT INTO PasteBin.IPLog (UserID, IP) VALUES (AUserID, AIPAddr);
	EXCEPTION
		WHEN OTHERS THEN
			NULL;	-- Don't care
	END;
	$$ LANGUAGE plpgsql;

	/* InsertPaste()	Creates and inserts a new paste into the database.
	 *
	 * If APassword is not NULL, then it is assumed that the paste is to be encrypted. All encrypted pastes are 
	 * marked private, regardless if APrivate is TRUE or FALSE.
	 *
	 * Returns: 0 on success, 1 if the supplied AUserID does not exist, and 2 otherwise.
	 */
	CREATE OR REPLACE FUNCTION PasteBin.InsertPaste(AUserID INTEGER, ATitle VARCHAR(256), AExpires TIMESTAMP, APrivate BOOLEAN, APassword VARCHAR(72), AIPAddr INET, ALanguage INT, AContents TEXT,
	                                                OUT Result INT, OUT OPasteID INTEGER) RETURNS RECORD AS $$
	DECLARE
		CEncryptAlgorithm CONSTANT TEXT := 'aes-cbc/pad:pkcs';	-- Rijndael-128
		VPassword VARCHAR(60);
		VContents BYTEA;
		VPrivate BOOLEAN;
	BEGIN
		IF (APassword IS NOT NULL) THEN
			VPassword := crypt(APassword, gen_salt('bf'));
			VContents := encrypt(AContents::BYTEA, APassword::BYTEA, CEncryptAlgorithm);
			VPrivate := TRUE;
		ELSE
			VPassword := NULL;
			VContents := AContents::BYTEA;
			VPrivate := coalesce(APrivate, FALSE);
		END IF;
		
		IF (AUserID IS NOT NULL) THEN
			IF EXISTS (SELECT 1 FROM PasteBin.Users WHERE UserID = AUserID) THEN
				OPasteID := INSERT INTO PasteBin.Pastes (Title, DateExpire, Private, EncryptPassword, MadeByIP, Language, Contents, UserID)
				            VALUES (ATitle, AExpires, VPrivate, VPassword, AIPAddr, ALanguage, VContents, AUserID) RETURNING PasteID;
			ELSE
				Result := 1;	-- User does not exist
			END IF;
		ELSE
			OPasteID := INSERT INTO PasteBin.Pastes (Title, DateExpire, Private, EncryptPassword, MadeByIP, Language, Contents, UserID)
			            VALUES (ATitle, AExpires, VPrivate, VPassword, AIPAddr, ALanguage, VContents, NULL) RETURNING PasteID;
			IF (OPasteID IS NOT NULL) THEN
				Result := 0;
			ELSE
				Result := 
		END IF;
	EXCEPTION
		WHEN OTHERS THEN
			Result := 2;	-- An exception has occurred.
	END;
	$$ LANGUAGE plpgsql;

	/* ValidatePassword()	Validates the provided password against the hash stored in the database.
	 *
	 * Valid values for AType:
	 *	0	- Validate the password against UserID matching AID.
	 *	1	- Validate the password against PasteID matching AID.
	 *
	 * Returns:
	 *	0	- Success (password does match).
	 *	1	- Supplied UserID (AID) does not exist.
	 *	2	- An exception has occurred.
	 *	5	- Invalid AType provided.
	 *	6	- Password validation attempts exhausted.
	 *	7	- Supplied PasteID (AID) does not exist.
	 *	8	- Passwords do not match.
	 */
	CREATE OR REPLACE FUNCTION PasteBin.ValidatePassword(AType INT, AID INTEGER, APassword VARCHAR(72), AByIP INET, AByUser INTEGER) RETURNS INT AS $$
	DECLARE
		VRawMaxAttempts TEXT;
		VMaxAttempts INTEGER;
		VPassword VARCHAR(60);
	BEGIN
		CASE AType
			WHEN 0 THEN	-- User login
				SELECT SettingValue INTO VRawMaxAttempts FROM PasteBin.SiteSettings WHERE SettingName = 'max_login_attempts' LIMIT 1;
			WHEN 1 THEN	-- Paste decryption password
				SELECT SettingValue INTO VRawMaxAttempts FROM PasteBin.SiteSettings WHERE SettingName = 'max_decrypt_attempts' LIMIT 1;
			ELSE
				RETURN 5;
		END CASE;

		VMaxAttempts := CAST(coalesce(VRawMaxAttempts, '5') AS INTEGER);
		
		IF ((SELECT COUNT(*) FROM PasteBin.PasswordPrompts WHERE (ByIP = AByIP OR ByUser = AByUser) AND WhenAt >= (LOCALTIMESTAMP - interval '15 minutes')) >= VMaxAttempts) THEN
			INSERT INTO PasteBin.PasswordPrompts (TypeOfPrompt, ByIP, ByUser, WhenAt) VALUES (AType, AByIP, AByUser, LOCALTIMESTAMP);
			RETURN 6;	-- Too many attempts
		ELSE
			CASE AType
				WHEN 0 THEN	-- User login
					IF (AID IS NOT NULL) THEN
						IF EXISTS (SELECT 1 FROM PasteBin.Users WHERE UserID = AID) THEN
							SELECT Password INTO VPassword FROM PasteBin.Users WHERE UserID = AID LIMIT 1;
						ELSE
							RETURN 1;
						END IF;
					ELSE
						RETURN 1;
					END IF;
				WHEN 1 THEN	-- Paste decryption
					IF (AID IS NOT NULL) THEN
						IF EXISTS (SELECT 1 FROM PasteBin.Pastes WHERE PasteID = AID) THEN
							SELECT EncryptPassword INTO VPassword FROM PasteBin.Pastes WHERE PasteID = AID LIMIT 1;
						ELSE
							RETURN 7;
						END IF;
					ELSE
						RETURN 7;
					END IF;
			END CASE;

			IF (VPassword = crypt(APassword, VPassword)) THEN
				RETURN 0;
			ELSE
				INSERT INTO PasteBin.PasswordPrompts (TypeOfPrompt, ByIP, ByUser, WhenAt) VALUES (AType, AByIP, AByUser, LOCALTIMESTAMP);
				RETURN 8;
			END IF;
		END IF;
	EXCEPTION
		WHEN OTHERS THEN
			RETURN 2;
	END;
	$$ LANGUAGE plpgsql;


	CREATE OR REPLACE FUNCTION PasteBin.ValidateLogin(AEMail VARCHAR(256), APassword VARCHAR(72), AByIP INET, ARemember BOOLEAN,
	                                          OUT Result INT, OUT OSeriesID BIGINT, OUT OToken VARCHAR(64)) RETURNS RECORD AS $$
	DECLARE
		VUserID INTEGER;
		VValidPassword INT;
	BEGIN
		IF EXISTS (SELECT 1 FROM PasteBin.Users WHERE EMail = AEMail) THEN
			SELECT UserID INTO VUserID FROM PasteBin.Users WHERE EMail = AEMail LIMIT 1;
			
			VValidPassword := PasteBin.ValidatePassword(0, VUserID, APassword, AByIP, NULL);
			IF (VValidPassword = 0) THEN
				IF (ARemember) THEN	-- Remember me?
					SELECT qry.Result, qry.OSeriesID, qry.OToken INTO Result, OSeriesID, OToken FROM PasteBin.InsertToken(VUserID, NULL) qry;
				ELSE
					Result := 0;
				END IF;
			ELSE
				Result := VValidPassword;
			END IF;
		ELSE
			Result := 1;
		END IF;
	EXCEPTION
		WHEN OTHERS THEN
			Result := 2;
	END;
	$$ LANGUAGE plpgsql;

	CREATE OR REPLACE FUNCTION PasteBin.ValidatePaste(APasteID INTEGER, APassword VARCHAR(72), AByIP INET, AByUser INTEGER,
	                                                  OUT Result INT, OUT OTitle VARCHAR(256), OUT OViews BIGINT, OUT ODateCreated TIMESTAMP, 
	                                                  OUT ODateExpire TIMESTAMP, OUT OIP INET, OUT OUserID INTEGER, OUT ODisplayName VARCHAR(256), 
	                                                  OUT OLanguage INT, OUT OContents TEXT) RETURNS RECORD AS $$
	DECLARE
		CDecryptAlgorithm CONSTANT TEXT := 'aes-cbc/pad:pkcs';
		VValidPassword INT;
		VPassword VARCHAR(60);
		VContents BYTEA;

		VTitle VARCHAR(256);
		VViews BIGINT;
		VDateCreated TIMESTAMP;
		VDateExpire TIMESTAMP;
		VIP INET;
		VUserID INTEGER;
		VDisplayName VARCHAR(256);
		VLanguage INT;

		VUserPerms INTEGER;
		VRawViewExpired TEXT;
		VViewExpired INTEGER;
	BEGIN
		IF EXISTS (SELECT 1 FROM PasteBin.Pastes WHERE PasteID = APasteID) THEN
			SELECT Title,  Views,  DateCreated,  DateExpire,  EncryptPassword, MadeByIP, Language,  Contents,  DisplayName,  PasteBin.Pastes.UserID
			INTO   VTitle, VViews, VDateCreated, VDateExpire, VPassword,       VIP,      VLanguage, VContents, VDisplayName, VUserID 
			FROM PasteBin.Pastes 
			LEFT OUTER JOIN PasteBin.Users ON (PasteBin.Users.UserID = PasteBin.Pastes.UserID) 
			WHERE PasteID = APasteID 
			LIMIT 1;

			IF (CURRENT_TIMESTAMP >= VDateExpire) THEN
				IF (AByUser IS NOT NULL) THEN
					SELECT Permission INTO VUserPerms FROM PasteBin.Users WHERE UserID = AByUser;
					SELECT SettingValue INTO VRawViewExpired FROM PasteBin.SiteSettings WHERE SettingName = 'view_expired_pastes_level';
					VViewExpired := CAST(coalesce(VRawViewExpired, '-1') AS INTEGER);
					
					IF NOT ((VViewExpired <> -1) AND (VUserPerms >= VViewExpired)) THEN
						Result := 7;
						RETURN;
					END IF;
				ELSE
					Result := 7;
					RETURN;
				END IF;
			END IF;
			
			IF (VPassword IS NOT NULL) THEN
				IF (APassword IS NOT NULL) THEN
					VValidPassword := PasteBin.ValidatePassword(1, APasteID, APassword, AByIP, AByUser);

					IF (VValidPassword = 0) THEN
						Result := 0;
						OTitle := VTitle;
						OViews := VViews;
						ODateCreated := VDateCreated;
						ODateExpire := VDateExpire;
						OIP := VIP;
						OUserID := VUserID;
						ODisplayName := VDisplayName;							
						OLanguage := VLanguage;
						
						OContents := decrypt(VContents, APassword::BYTEA, CDecryptAlgorithm);
					ELSE
						Result := VValidPassword;
					END IF;
				ELSE
					Result := 9;	-- Password not supplied.
				END IF;
			ELSE
				Result := 0;
				OTitle := VTitle;
				OViews := VViews;
				ODateCreated := VDateCreated;
				ODateExpire := VDateExpire;
				OIP := VIP;
				OUserID := VUserID;
				ODisplayName := VDisplayName;							
				OLanguage := VLanguage;
				OContents := VContents::TEXT;
			END IF;
		ELSE
			Result := 7;
		END IF;
	EXCEPTION
		WHEN OTHERS THEN
			Result := 2;
	END;
	$$ LANGUAGE plpgsql;

	CREATE OR REPLACE FUNCTION PasteBin.ChangeUserPassword(AUserID INTEGER, AOldPassword VARCHAR(72), ANewPassword VARCHAR(72), AByIP INET) RETURNS INT AS $$
	DECLARE
		VValidPassword INT;
	BEGIN
		VValidPassword := PasteBin.ValidatePassword(0, AUserID, AOldPassword, AByIP, LOCALTIMESTAMP, AUserID);
		IF (VValidPassword = 0) THEN
			UPDATE PasteBin.Users SET Password = crypt(ANewPassword, gen_salt('bf', 12)) WHERE UserID = AUserID;
		END IF;

		RETURN VValidPassword;
	END;
	$$ LANGUAGE plpgsql;

COMMIT;

