require('dotenv').config();

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const logger = require('./logger'); // Importar el logger
const JWT_SECRET = process.env.JWT_SECRET; 

const app = express();
const PORT = 3000;

// Middleware para que el servidor pueda leer el JSON que envíes desde Postman
app.use(express.json());

// Conexión a la base de datos
const db = new sqlite3.Database('./usuarios.db');

logger.info('=== SERVIDOR INICIADO ===');
logger.debug('Base de datos conectada: usuarios.db');
logger.debug('JWT_SECRET configurado correctamente');

// Función para generar JWT usando jsonwebtoken
function generarJWT(payload) {
    logger.debug(`Generando token JWT para usuario ID: ${payload.user_id}`);
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

// Función para verificar JWT usando Python
async function verificarJWT(token) {
    logger.debug('Verificando token con Python handler');
    try {
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

// ENDPOINT: POST /login
app.post('/login', async (req, res) => {
    logger.debug('=== SOLICITUD DE LOGIN ===');
    
    const { email, password } = req.body;

    logger.debug('Validando credenciales de usuario');

    if (!email || !password) {
        logger.warning('Login rechazado: email o contraseña no proporcionados');
        return res.status(400).json({ error: "Email y contraseña son requeridos" });
    }

    logger.debug('Buscando usuario en base de datos');
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

        logger.debug('Usuario encontrado, verificando contraseña');
        
        try {
            const match = await bcrypt.compare(password, user.password);
            
            if (match) {
                logger.info(`Login exitoso para usuario ID: ${user.id}`);
                logger.debug('Generando token de autenticación...');
                
                const payload = {
                    user_id: user.id,
                    email: user.email,
                    role: user.role || 'user'
                };
                
                try {
                    const token = generarJWT(payload);
                    logger.debug('Token generado exitosamente');
                    
                    res.status(200).json({ 
                        message: "Login exitoso",
                        token: token,
                        email: user.email,
                        role: user.role 
                    });
                    
                } catch (jwtError) {
                    logger.error(`Error al generar token JWT: ${jwtError.message}`);
                    res.status(500).json({ 
                        error: "Error al generar token de autenticación",
                        detalle: jwtError.message 
                    });
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

// ENDPOINT: POST /registro
app.post('/registro', async (req, res) => {
    logger.debug('=== SOLICITUD DE REGISTRO ===');
    
    const { email, password } = req.body;

    logger.debug('Validando requisitos de contraseña (longitud entre 9 caracteres)');

    // 1. Validar datos de entrada (Password mayor a 8 y menor a 10)
    if (!email || !password || password.length <= 8 || password.length >= 10) {
        logger.warning('Registro rechazado: la contraseña no cumple con los requisitos de longitud');
        return res.status(400).send("Error 400: Credenciales Invalidas");
    }
    // Validar formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        logger.warning('Registro rechazado: formato de email inválido');
        return res.status(400).send("Error 400: Formato de email inválido");
    }

    logger.debug('Validaciones iniciales superadas');
    logger.debug('Verificando si el email ya está registrado');

    // 2. Verificar duplicados (Email existente)
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

        logger.debug('Email disponible, procediendo con el registro');
        logger.debug('Cifrando contraseña con bcrypt...');

        // 3. Si no es duplicado, cifrar la contraseña con bcrypt
        try {
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            logger.debug('Contraseña cifrada correctamente');

            // 4. Guardar en la base de datos
            logger.debug('Guardando nuevo usuario en base de datos');
            const sqlInsert = `INSERT INTO usuarios (email, password) VALUES (?, ?)`;
            
            db.run(sqlInsert, [email, hashedPassword], function(err) {
                if (err) {
                    logger.error(`Error al guardar usuario: ${err.message}`);
                    return res.status(500).send("Error al guardar usuario");
                }
                
                logger.info(`Usuario registrado exitosamente - ID: ${this.lastID}`);
                
                // 5. Éxito
                res.status(201).send("Success 201: Usuario Registrado");
            });

        } catch (error) {
            logger.error(`Error al cifrar contraseña: ${error.message}`);
            res.status(500).send("Error al cifrar contraseña");
        }
    });
});

// ENDPOINT PUT /cambiar-rol/:email
app.put('/cambiar-rol/:email', (req, res) => {
    logger.debug('=== SOLICITUD DE CAMBIO DE ROL ===');
    
    const userEmail = req.params.email;
    const { newRole } = req.body;

    logger.debug('Validando nuevo rol proporcionado');

    if (!newRole) {
        logger.warning('Cambio de rol rechazado: no se especificó el nuevo rol');
        return res.status(400).json({ error: "Debes proporcionar el nuevo rol (newRole)." });
    }

    logger.debug('Buscando usuario en base de datos');
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

        logger.debug('Usuario encontrado, actualizando rol');
        
        const sqlUpdate = "UPDATE usuarios SET role = ? WHERE email = ?";
        
        db.run(sqlUpdate, [newRole, userEmail], function(err) {
            if (err) {
                logger.error(`Error al actualizar rol: ${err.message}`);
                return res.status(500).json({ error: err.message });
            }
            
            logger.info(`Rol actualizado exitosamente para usuario: ${userEmail} a ${newRole}`);
            
            res.status(200).json({ 
                message: `Rol de ${userEmail} actualizado a ${newRole}.`,
                cambios: this.changes 
            });
        });
    });
});

// ENDPOINT PUT /cambiar-password
app.put('/usuarios/cambiar-password/:email', (req, res) => {
    logger.debug('=== SOLICITUD DE CAMBIO DE CONTRASEÑA ===');
    
    const userEmail = req.params.email;
    const { oldPassword, newPassword } = req.body;

    logger.debug('Procesando cambio de contraseña para usuario');
    logger.debug('Contraseña antigua recibida para verificación');
    logger.debug('Nueva contraseña recibida para actualización');

    if (!oldPassword || !newPassword) {
        logger.warning('Cambio de contraseña rechazado: datos incompletos');
        return res.status(400).json({ error: "Datos incompletos." });
    }

    logger.debug('Buscando usuario en base de datos');
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

        logger.debug('Usuario encontrado, verificando contraseña antigua');

        try {
            const match = await bcrypt.compare(oldPassword, user.password);
            
            if (!match) {
                logger.warning('Cambio de contraseña rechazado: contraseña antigua incorrecta');
                return res.status(401).json({ error: "La contraseña antigua no coincide." });
            }

            logger.debug('Contraseña antigua verificada correctamente');
            logger.debug('Cifrando nueva contraseña...');
            
            const saltRounds = 10;
            const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);
            logger.debug('Nueva contraseña cifrada correctamente');

            logger.debug('Actualizando contraseña en base de datos');
            const sqlUpdate = "UPDATE usuarios SET password = ? WHERE email = ?";
            db.run(sqlUpdate, [hashedNewPassword, userEmail], function(err) {
                if (err) {
                    logger.error(`Error al actualizar contraseña: ${err.message}`);
                    return res.status(500).json({ error: err.message });
                }
                
                logger.info(`Contraseña actualizada exitosamente para usuario: ${userEmail}`);
                
                res.status(200).json({ 
                    message: `Contraseña de ${userEmail} actualizada.`,
                    cambios: this.changes 
                });
            });

        } catch (error) {
            logger.error(`Error en el proceso de cifrado: ${error.message}`);
            res.status(500).json({ error: "Error en el proceso de cifrado." });
        }
    });
});

// Middleware para verificar el JWT en rutas protegidas 
function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 

    logger.debug('=== VERIFICANDO TOKEN DE AUTENTICACIÓN ===');

    if (!token) {
        logger.warning('Acceso denegado: token no proporcionado');
        return res.status(401).json({ error: 'Acceso denegado. Token requerido.' });
    }

    try {
        logger.debug('Validando token JWT...');
        const decoded = jwt.verify(token, JWT_SECRET);
        logger.debug(`Token válido, usuario autenticado correctamente - ID: ${decoded.user_id}`);
        req.usuario = decoded;
        next();
    } catch (err) {
        logger.warning(`Acceso denegado: token inválido o expirado - ${err.message}`);
        return res.status(403).json({ error: 'Token inválido o expirado.' });
    }
}

// ENDPOINT POST /comprar
app.post('/comprar', verificarToken, (req, res) => {
    logger.debug('=== SOLICITUD DE COMPRA ===');
    
    const { producto_id, cantidad } = req.body;
    const usuario_id = req.usuario.user_id;

    logger.debug(`Procesando compra para usuario autenticado ID: ${usuario_id}`);
    logger.debug('Validando datos de la compra');

    // Validación: campos requeridos
    if (producto_id === undefined || cantidad === undefined) {
        logger.warning(`Compra rechazada: datos incompletos para usuario ${usuario_id}`);
        return res.status(400).json({ error: "producto_id y cantidad son requeridos." });
    }

    // Validación: producto_id debe ser entero positivo
    if (!Number.isInteger(producto_id) || producto_id <= 0) {
        logger.warning(`Compra rechazada: producto_id inválido (${producto_id}) para usuario ${usuario_id}`);
        return res.status(400).json({ error: "producto_id debe ser un número entero positivo." });
    }

    // Validación: cantidad debe ser entero positivo
    if (!Number.isInteger(cantidad) || cantidad <= 0) {
        logger.warning(`Compra rechazada: cantidad inválida (${cantidad}) para usuario ${usuario_id}`);
        return res.status(400).json({ error: "La cantidad debe ser un número entero positivo." });
    }

    logger.debug(`Buscando producto ID: ${producto_id}`);
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

        logger.debug(`Producto encontrado: ${producto.nombre} - Stock: ${producto.stock} - Precio: ${producto.precio}`);
        
        // Verificar stock suficiente
        if (producto.stock < cantidad) {
            logger.warning(`Compra rechazada: stock insuficiente para producto ${producto_id} - Solicitado: ${cantidad}, Disponible: ${producto.stock}`);
            return res.status(400).json({ 
                error: "Stock insuficiente.",
                stock_disponible: producto.stock
            });
        }

        const total = producto.precio * cantidad;
        logger.debug(`Stock disponible, procesando compra - Total: ${total}`);

        // Registrar la compra
        logger.debug('Registrando compra en base de datos');
        const sqlInsert = `
            INSERT INTO compras (usuario_id, producto_id, cantidad, total, fecha)
            VALUES (?, ?, ?, ?, datetime('now'))
        `;
        db.run(sqlInsert, [usuario_id, producto_id, cantidad, total], function(err) {
            if (err) {
                logger.error(`Error al registrar compra: ${err.message}`);
                return res.status(500).json({ error: "Error al registrar la compra." });
            }

            const compra_id = this.lastID;
            logger.info(`Compra registrada exitosamente - ID: ${compra_id} - Usuario: ${usuario_id} - Producto: ${producto.nombre} - Cantidad: ${cantidad} - Total: ${total}`);

            // Descontar stock
            logger.debug('Actualizando stock del producto');
            const sqlStock = "UPDATE productos SET stock = stock - ? WHERE id = ?";
            db.run(sqlStock, [cantidad, producto_id], (err) => {
                if (err) {
                    logger.error(`Error al actualizar stock: ${err.message}`);
                    return res.status(500).json({ error: "Error al actualizar stock." });
                }

                logger.debug('Stock actualizado correctamente');
                logger.info(`Compra completada con éxito para usuario ${usuario_id}`);
                
                res.status(201).json({
                    message: "Compra registrada exitosamente.",
                    compra_id: compra_id,
                    producto: producto.nombre,
                    cantidad: cantidad,
                    total: `$${total.toFixed(2)}`
                });
            });
        });
    });
});

// Levantar el servidor
app.listen(PORT, () => {
    logger.info(`Servidor corriendo en http://localhost:${PORT}`);
    logger.debug('Endpoints disponibles:');
    logger.debug('  POST   /login');
    logger.debug('  POST   /registro');
    logger.debug('  PUT    /cambiar-rol/:email');
    logger.debug('  PUT    /usuarios/cambiar-password/:email');
    logger.debug('  POST   /comprar (requiere autenticación)');
});