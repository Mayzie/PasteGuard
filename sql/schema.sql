BEGIN TRANSACTION;

	DROP SCHEMA IF EXISTS PasteBin CASCADE;

	CREATE SCHEMA PasteBin;

	SET search_path = PasteBin, '$user', public;
	SET CONSTRAINTS ALL DEFERRED;

	--- Begin table creation ---
	
	CREATE TABLE PasteBin.Users (
		UserID		SERIAL		NOT NULL,
		DisplayName	VARCHAR(256)	NOT NULL,
		EMail		VARCHAR(256)	NOT NULL UNIQUE,
		Password	VARCHAR(60)	NOT NULL,
		DateRegistered	TIMESTAMP	NOT NULL	DEFAULT LOCALTIMESTAMP,
		Permission	INTEGER		NOT NULL	DEFAULT 1,
		---
		PRIMARY KEY (UserID)
	);
	
	CREATE TABLE PasteBin.Tokens (
		UserID		INTEGER		NOT NULL,
		SeriesID	BIGINT		NOT NULL,
		Token		VARCHAR(64)	NOT NULL,
		DateCreated	TIMESTAMP	NOT NULL	DEFAULT LOCALTIMESTAMP,
		---
		FOREIGN KEY (UserID) REFERENCES PasteBin.Users(UserID) ON DELETE CASCADE,
		PRIMARY KEY (UserID, SeriesID)
	);
	
	CREATE TABLE PasteBin.IPLog (
		UserID		INTEGER		NOT NULL,
		IP		INET		NOT NULL,
		--
		FOREIGN KEY (UserID) REFERENCES PasteBin.Users(UserID) ON DELETE CASCADE,
		PRIMARY KEY (UserID, IP)
	);
	
	CREATE TABLE PasteBin.Pastes (
		PasteID		SERIAL		NOT NULL,
		Title		VARCHAR(256)	NOT NULL	DEFAULT 'Untitled',
		Views		BIGINT		NOT NULL	DEFAULT 0,
		DateCreated	TIMESTAMP	NOT NULL	DEFAULT LOCALTIMESTAMP,
		DateExpire	TIMESTAMP,
		Private		BOOLEAN		NOT NULL	DEFAULT FALSE,
		EncryptPassword	VARCHAR(60),
		MadeByIP	INET		NOT NULL,
		Language	INT		NOT NULL	DEFAULT 0,
		Contents	BYTEA		NOT NULL,
		UserID		INTEGER,
		---
		FOREIGN KEY (UserID) REFERENCES PasteBin.Users(UserID),
		PRIMARY KEY (PasteID)
	);
	
	CREATE TABLE PasteBin.SiteSettings (
		SettingName	VARCHAR(256)	NOT NULL,
		SettingValue	TEXT		NOT NULL,
		SettingType	SMALLINT	NOT NULL,
		SettingDesc	TEXT		NOT NULL	DEFAULT '<em>Description unspecified</em>',
		---
		PRIMARY KEY (SettingName)
	);
	
	CREATE TABLE PasteBin.PasswordPrompts (
		TypeOfPrompt	INT		NOT NULL,
		ByIP		INET		NOT NULL,
		ByUser		INTEGER,
		WhenAt		TIMESTAMP	NOT NULL	DEFAULT LOCALTIMESTAMP,
		---
		FOREIGN KEY (ByUser) REFERENCES PasteBin.Users(UserID)
	);

		
	--- Begin index creation ---

	CREATE INDEX Index_Emails ON PasteBin.Users USING hash (EMail);
	CREATE UNIQUE INDEX Index_LoginTokens ON PasteBin.Tokens USING btree (UserID, SeriesID);
	CREATE INDEX Index_UserIPAddr ON PasteBin.IPLog USING btree (IP);
	CREATE INDEX Index_PasteTitles ON PasteBin.Pastes USING hash (Title);
	CREATE INDEX Index_PasteLanguages ON PasteBin.Pastes USING btree (Language);
	CREATE INDEX Index_PasteCreatedDate ON PasteBin.Pastes USING btree (DateCreated, Private);
	CREATE INDEX Index_PasteCreatedBy ON PasteBin.Pastes USING btree (UserID, Private);
	CREATE INDEX Index_AllPastesCreatedBy ON PasteBin.Pastes USING btree (UserID);
	CREATE INDEX Index_Settings ON PasteBin.SiteSettings USING hash (SettingName);
	CREATE INDEX Index_PasswordPromptsIP ON PasteBin.PasswordPrompts USING btree (WhenAt, ByIP);
	CREATE INDEX Index_PasswordPromptsUser ON PasteBin.PasswordPrompts USING btree (WhenAt, ByUser);
	CREATE INDEX Index_PasswordPrompts ON PasteBin.PasswordPrompts USING btree (WhenAt, ByUser, ByIP); 

	VACUUM FULL;

COMMIT;
