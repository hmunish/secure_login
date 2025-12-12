CREATE DATABASE IF NOT EXISTS secure_login;
USE secure_login;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) UNIQUE,
  password_hash VARCHAR(255),
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  failed_attempts INT DEFAULT 0,
  lockout_until DATETIME NULL
);

CREATE TABLE ip_failures (
  ip VARCHAR(45) PRIMARY KEY,
  attempts INT DEFAULT 0,
  last_failed DATETIME
);

INSERT INTO users (username,password_hash,first_name,last_name)
VALUES ('testuser','$2y$10$73q4qjTO/ojultk17Lb5IOvB3FN6cOyuMF7DZV2v2AMImCO/8tpsG','Test','User');