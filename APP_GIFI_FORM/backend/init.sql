-- Création de la table users
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Création de la table stock
CREATE TABLE IF NOT EXISTS stock (
    id SERIAL PRIMARY KEY,
    sn VARCHAR(255) NOT NULL,
    article VARCHAR(255) NOT NULL,
    etat VARCHAR(100) NOT NULL,
    type_stock VARCHAR(10) NOT NULL CHECK (type_stock IN ('input', 'output')),
    tag_integration CHAR(1) DEFAULT 'x',
    notes TEXT,
    ticket_bmc VARCHAR(255),
    nom_prenom VARCHAR(255),
    cause_installation_materiel TEXT,
    produits_installes TEXT,
    cause_recuperation_materiel TEXT,
    produits_recuperes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Ajouts idempotents si la table existe déjà
ALTER TABLE stock ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE stock ADD COLUMN IF NOT EXISTS ticket_bmc VARCHAR(255);
ALTER TABLE stock ADD COLUMN IF NOT EXISTS nom_prenom VARCHAR(255);
ALTER TABLE stock ADD COLUMN IF NOT EXISTS cause_installation_materiel TEXT;
ALTER TABLE stock ADD COLUMN IF NOT EXISTS produits_installes TEXT;
ALTER TABLE stock ADD COLUMN IF NOT EXISTS cause_recuperation_materiel TEXT;
ALTER TABLE stock ADD COLUMN IF NOT EXISTS produits_recuperes TEXT;

-- Index pour améliorer les performances des requêtes
CREATE INDEX idx_stock_type ON stock(type_stock);
CREATE INDEX idx_stock_tag ON stock(tag_integration);
CREATE INDEX idx_users_username ON users(username);

-- Note: L'utilisateur admin sera créé automatiquement par l'application au premier démarrage

-- Table des articles
CREATE TABLE IF NOT EXISTS articles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_articles_name ON articles(name);
