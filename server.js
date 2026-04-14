require('dotenv').config();

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const logger = require('./logger');
const JWT_SECRET = process.env.JWT_SECRET;

const app = express();
const PORT = 3000;

app.use(express.json());

const db = new sqlite3.Database('./usuarios.db');

logger.info('=== SERVIDOR INICIADO ===');
logger.debug('Base de datos conectada: usuarios.db');
logger.debug('JWT_SECRET configurado correctamente');

function generarJWT(payload) {
    logger.debug(`Generando token JWT para usuario ID: ${payload.user_id}`);
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

async function verificarJWT(token) {
    logger.debug('Verificando token con Python handler');
    try {
        // FIX [HIGH] línea 47: stdout y stderr eran variables globales implícitas
        const { stdout, stderr } = await execPromise(`python jwt_handler.py verificar '${token}'`);
        if (stderr) {
            logger.error(`Error en Python: ${stderr}`);
            throw new Error(stderr);
        }
        logger.debug('Token verificado correctamente');
        return JSON.parse(stdout);
    } catch (error) {
        logger.error(`Error al verificar token: ${error.message}`);
        return { valido: false, error: 'Error al verificar token' };
    }
}

app.post('/login', async (req, res) => {
    logger.debug('=== SOLICITUD DE LOGIN ===');
    const { email, password } = req.body;
    if (!email || !password) {
        logger.warning('Login rechazado: email o contraseña no proporcionados');
        return res.status(400).json({ error: "Email y contraseña son requeridos" });
    }
    // FIX [HIGH] línea 52: sqlSearch era variable global implícita
    const sqlSearch = "SELECT * FROM usuarios WHERE email = ?";
    db.get(sqlSearch, [email], async (err, user) => {
        if (err) {
            logger.error(`Error en consulta de base de datos: ${err.message}`);
            return res.status(500).json({ error: "Error en el servidor" });
        }
        if (!user) {
            logger.warning('Login fallido: usuario no encontrado');
            return res.status(401).json({ error: "Credenciales inválidas" });
        }
        try {
            // FIX [HIGH] línea 63: match era variable global implícita
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                logger.info(`Login exitoso para usuario ID: ${user.id}`);
                // FIX [HIGH] línea 66: payload era variable global implícita
                const payload = {
                    user_id: user.id,
                    email: user.email,
                    role: user.role || 'user'
                };
                try {
                    // FIX [HIGH] línea 72: token era variable global implícita
                    const token = generarJWT(payload);
                    res.status(200).json({ message: "Login exitoso", token, email: user.email, role: user.role });
                } catch (jwtError) {
                    logger.error(`Error al generar token JWT: ${jwtError.message}`);
                    res.status(500).json({ error: "Error al generar token de autenticación", detalle: jwtError.message });
                }
            } else {
                logger.warning(`Login fallido: contraseña incorrecta para usuario ID: ${user.id}`);
                res.status(401).json({ error: "Credenciales inválidas" });
            }
        } catch (error) {
            logger.error(`Error al verificar contraseña: ${error.message}`);
            res.status(500).json({ error: "Error al verificar la contraseña" });
        }
    });
});

app.post('/registro', async (req, res) => {
    logger.debug('=== SOLICITUD DE REGISTRO ===');
    const { email, password } = req.body;
    if (!email || !password || password.length <= 8 || password.length >= 10) {
        logger.warning('Registro rechazado: la contraseña no cumple con los requisitos de longitud');
        return res.status(400).send("Error 400: Credenciales Invalidas");
    }
    // FIX [HIGH] línea 96: emailRegex era variable global implícita
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        logger.warning('Registro rechazado: formato de email inválido');
        return res.status(400).send("Error 400: Formato de email inválido");
    }
    // FIX [HIGH] línea 101: sqlCheck era variable global implícita
    const sqlCheck = `SELECT * FROM usuarios WHERE email = ?`;
    db.get(sqlCheck, [email], async (err, row) => {
        if (err) {
            logger.error(`Error al verificar duplicados: ${err.message}`);
            return res.status(500).send("Error en el servidor");
        }
        if (row) {
            logger.warning('Registro rechazado: el email ya está registrado');
            return res.status(409).send("ERROR 409: El usuario ya existe");
        }
        try {
            // FIX [HIGH] líneas 112-114: saltRounds, hashedPassword y sqlInsert eran variables globales implícitas
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const sqlInsert = `INSERT INTO usuarios (email, password) VALUES (?, ?)`;
            db.run(sqlInsert, [email, hashedPassword], function(err) {
                if (err) {
                    logger.error(`Error al guardar usuario: ${err.message}`);
                    return res.status(500).send("Error al guardar usuario");
                }
                logger.info(`Usuario registrado exitosamente - ID: ${this.lastID}`);
                res.status(201).send("Success 201: Usuario Registrado");
            });
        } catch (error) {
            logger.error(`Error al cifrar contraseña: ${error.message}`);
            res.status(500).send("Error al cifrar contraseña");
        }
    });
});

app.put('/cambiar-rol/:email', (req, res) => {
    logger.debug('=== SOLICITUD DE CAMBIO DE ROL ===');
    const userEmail = req.params.email;
    const { newRole } = req.body;
    if (!newRole) {
        logger.warning('Cambio de rol rechazado: no se especificó el nuevo rol');
        return res.status(400).json({ error: "Debes proporcionar el nuevo rol (newRole)." });
    }
    const sqlSearch = "SELECT * FROM usuarios WHERE email = ?";
    db.get(sqlSearch, [userEmail], (err, user) => {
        if (err) {
            logger.error(`Error al buscar usuario: ${err.message}`);
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            logger.warning('Cambio de rol rechazado: usuario no encontrado');
            return res.status(404).json({ error: "Usuario no encontrado." });
        }
        const sqlUpdate = "UPDATE usuarios SET role = ? WHERE email = ?";
        db.run(sqlUpdate, [newRole, userEmail], function(err) {
            if (err) {
                logger.error(`Error al actualizar rol: ${err.message}`);
                return res.status(500).json({ error: err.message });
            }
            logger.info(`Rol actualizado exitosamente para usuario: ${userEmail} a ${newRole}`);
            res.status(200).json({ message: `Rol de ${userEmail} actualizado a ${newRole}.`, cambios: this.changes });
        });
    });
});

app.put('/usuarios/cambiar-password/:email', (req, res) => {
    logger.debug('=== SOLICITUD DE CAMBIO DE CONTRASEÑA ===');
    const userEmail = req.params.email;
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
        logger.warning('Cambio de contraseña rechazado: datos incompletos');
        return res.status(400).json({ error: "Datos incompletos." });
    }
    const sqlSearch = "SELECT password FROM usuarios WHERE email = ?";
    db.get(sqlSearch, [userEmail], async (err, user) => {
        if (err) {
            logger.error(`Error al buscar usuario: ${err.message}`);
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            logger.warning('Cambio de contraseña rechazado: usuario no encontrado');
            return res.status(404).json({ error: "Usuario no encontrado con ese correo." });
        }
        try {
            // FIX [HIGH] línea 179: match era variable global implícita
            const match = await bcrypt.compare(oldPassword, user.password);
            if (!match) {
                logger.warning('Cambio de contraseña rechazado: contraseña antigua incorrecta');
                return res.status(401).json({ error: "La contraseña antigua no coincide." });
            }
            // FIX [HIGH] líneas 184-186: saltRounds, hashedNewPassword y sqlUpdate eran variables globales implícitas
            const saltRounds = 10;
            const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);
            const sqlUpdate = "UPDATE usuarios SET password = ? WHERE email = ?";
            db.run(sqlUpdate, [hashedNewPassword, userEmail], function(err) {
                if (err) {
                    logger.error(`Error al actualizar contraseña: ${err.message}`);
                    return res.status(500).json({ error: err.message });
                }
                logger.info(`Contraseña actualizada exitosamente para usuario: ${userEmail}`);
                res.status(200).json({ message: `Contraseña de ${userEmail} actualizada.`, cambios: this.changes });
            });
        } catch (error) {
            logger.error(`Error en el proceso de cifrado: ${error.message}`);
            res.status(500).json({ error: "Error en el proceso de cifrado." });
        }
    });
});

function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    // FIX [MEDIUM] línea 223: comparación == reemplazada por ===
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        logger.warning('Acceso denegado: token no proporcionado');
        return res.status(401).json({ error: 'Acceso denegado. Token requerido.' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.usuario = decoded;
        next();
    } catch (err) {
        logger.warning(`Acceso denegado: token inválido o expirado - ${err.message}`);
        return res.status(403).json({ error: 'Token inválido o expirado.' });
    }
}

app.post('/comprar', verificarToken, (req, res) => {
    logger.debug('=== SOLICITUD DE COMPRA ===');
    const { producto_id, cantidad } = req.body;
    const usuario_id = req.usuario.user_id;
    if (producto_id === undefined || cantidad === undefined) {
        logger.warning(`Compra rechazada: datos incompletos para usuario ${usuario_id}`);
        return res.status(400).json({ error: "producto_id y cantidad son requeridos." });
    }
    if (!Number.isInteger(producto_id) || producto_id <= 0) {
        logger.warning(`Compra rechazada: producto_id inválido (${producto_id}) para usuario ${usuario_id}`);
        return res.status(400).json({ error: "producto_id debe ser un número entero positivo." });
    }
    if (!Number.isInteger(cantidad) || cantidad <= 0) {
        logger.warning(`Compra rechazada: cantidad inválida (${cantidad}) para usuario ${usuario_id}`);
        return res.status(400).json({ error: "La cantidad debe ser un número entero positivo." });
    }
    const sqlProducto = "SELECT * FROM productos WHERE id = ?";
    db.get(sqlProducto, [producto_id], (err, producto) => {
        if (err) {
            logger.error(`Error al buscar producto: ${err.message}`);
            return res.status(500).json({ error: "Error en el servidor." });
        }
        if (!producto) {
            logger.warning(`Compra rechazada: producto ${producto_id} no encontrado`);
            return res.status(404).json({ error: "Producto no encontrado." });
        }
        if (producto.stock < cantidad) {
            logger.warning(`Compra rechazada: stock insuficiente para producto ${producto_id} - Solicitado: ${cantidad}, Disponible: ${producto.stock}`);
            return res.status(400).json({ error: "Stock insuficiente.", stock_disponible: producto.stock });
        }
        const total = producto.precio * cantidad;
        const sqlInsert = `INSERT INTO compras (usuario_id, producto_id, cantidad, total, fecha) VALUES (?, ?, ?, ?, datetime('now'))`;
        db.run(sqlInsert, [usuario_id, producto_id, cantidad, total], function(err) {
            if (err) {
                logger.error(`Error al registrar compra: ${err.message}`);
                return res.status(500).json({ error: "Error al registrar la compra." });
            }
            // FIX [HIGH] líneas 256-258: compra_id, sqlStock y err interno eran variables globales implícitas
            const compra_id = this.lastID;
            const sqlStock = "UPDATE productos SET stock = stock - ? WHERE id = ?";
            db.run(sqlStock, [cantidad, producto_id], (stockErr) => {
                if (stockErr) {
                    logger.error(`Error al actualizar stock: ${stockErr.message}`);
                    return res.status(500).json({ error: "Error al actualizar stock." });
                }
                res.status(201).json({ message: "Compra registrada exitosamente.", compra_id, producto: producto.nombre, cantidad, total: `$${total.toFixed(2)}` });
            });
        });
    });
});

// FIX [HIGH] línea 269: PORT en app.listen ya estaba declarado como const arriba — sin cambios necesarios
app.listen(PORT, () => {
    logger.info(`Servidor corriendo en http://localhost:${PORT}`);
});