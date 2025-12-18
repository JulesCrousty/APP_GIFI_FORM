-- Création de la table users
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table des articles
CREATE TABLE IF NOT EXISTS articles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_articles_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Création de la table stock
CREATE TABLE IF NOT EXISTS stock (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sn VARCHAR(255) NOT NULL,
    article VARCHAR(255) NOT NULL,
    etat VARCHAR(100) NOT NULL,
    type_stock ENUM('input', 'output') NOT NULL,
    tag_integration CHAR(1) DEFAULT 'x',
    notes TEXT,
    ticket_bmc VARCHAR(255),
    nom_prenom VARCHAR(255),
    cause_installation_materiel TEXT,
    produits_installes TEXT,
    cause_recuperation_materiel TEXT,
    produits_recuperes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_stock_type (type_stock),
    INDEX idx_stock_tag (tag_integration)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
