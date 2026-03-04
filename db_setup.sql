-- ============================================================
--  LEZIONE SQL INJECTION  |  Database di prova
--  Scopo: SOLO DIDATTICO – ambiente isolato/locale
-- ============================================================

CREATE DATABASE IF NOT EXISTS sqli_demo
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE sqli_demo;

-- -----------------------------------------------------------
-- Tabella utenti (bersaglio principale degli attacchi)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS utenti (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50)  NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,          -- in prod: hash; qui plain per chiarezza
    email    VARCHAR(100) NOT NULL,
    ruolo    ENUM('user','admin') DEFAULT 'user',
    attivo   TINYINT(1) DEFAULT 1
);

INSERT INTO utenti (username, password, email, ruolo) VALUES
('admin',   'SuperSecret99!', 'admin@demo.local',   'admin'),
('mario',   'mario1234',      'mario@demo.local',   'user'),
('luigi',   'luigi5678',      'luigi@demo.local',   'user'),
('hacker',  'hacker000',      'hacker@demo.local',  'user');

-- -----------------------------------------------------------
-- Tabella ordini (dati sensibili collegati agli utenti)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS ordini (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    utente_id  INT NOT NULL,
    prodotto   VARCHAR(100) NOT NULL,
    importo    DECIMAL(8,2) NOT NULL,
    data_ord   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (utente_id) REFERENCES utenti(id)
);

INSERT INTO ordini (utente_id, prodotto, importo) VALUES
(2, 'Laptop Pro',   1299.99),
(2, 'Mouse RGB',      29.90),
(3, 'Tastiera Mech', 89.50),
(1, 'Server Rack',  4999.00);

-- -----------------------------------------------------------
-- Tabella log (utile per dimostrare attacchi all'Availability)
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_accessi (
    id        INT AUTO_INCREMENT PRIMARY KEY,
    utente    VARCHAR(50),
    ip        VARCHAR(45),
    esito     ENUM('OK','FAIL') DEFAULT 'OK',
    ts        DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO log_accessi (utente, ip, esito) VALUES
('admin', '192.168.1.1', 'OK'),
('mario', '10.0.0.5',    'OK'),
('luigi', '10.0.0.6',    'FAIL');
