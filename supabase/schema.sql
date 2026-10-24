-- Esquema de la base de datos del laboratorio 2FA (TOTP).
-- Pegar en Supabase -> SQL Editor -> New query -> Run.

create table if not exists users (
    id            uuid primary key default gen_random_uuid(),
    username      text not null unique,
    password_hash text not null,                 -- scrypt + sal (ver app/security.py)
    created_at    timestamp default now()
);

create table if not exists mfa_config (
    user_id       uuid primary key references users (id),
    secret_base32 text not null,                 -- semilla CIFRADA: aes256gcm$... (ver app/crypto.py)
    status        text not null default 'PENDING_VERIFICATION',  -- PENDING_VERIFICATION | ACTIVE
    created_at    timestamp default now(),
    activated_at  timestamp
);

create table if not exists backup_codes (
    id        uuid primary key default gen_random_uuid(),
    user_id   uuid references users (id),
    code_hash text not null,                     -- SHA-256 del código (nunca el código en claro)
    used      boolean default false
);

-- Consultas útiles para la demo ------------------------------------------------

-- Usuarios con su estado de 2FA y la semilla cifrada
-- select u.username, m.status, m.secret_base32, m.activated_at
-- from users u left join mfa_config m on m.user_id = u.id;

-- Códigos de respaldo usados / disponibles por usuario
-- select u.username, count(*) filter (where b.used) as usados, count(*) filter (where not b.used) as disponibles
-- from users u join backup_codes b on b.user_id = u.id group by u.username;

-- Borrar todos los datos (en este orden por las llaves foráneas)
-- delete from backup_codes; delete from mfa_config; delete from users;
