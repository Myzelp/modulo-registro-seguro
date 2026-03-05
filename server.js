require('dotenv').config();

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');        
const JWT_SECRET = process.env.JWT_SECRET; 

const app = express();
const PORT = 3000;

// Middleware para que el servidor pueda leer el JSON que envíes desde Postman
app.use(express.json());

// Conexión a la base de datos
const db = new sqlite3.Database('./usuarios.db');

// Función para generar JWT usando jsonwebtoken
function generarJWT(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

// Función para verificar JWT usando Python
async function verificarJWT(token) {
    try {
        const { stdout, stderr } = await execPromise(`python jwt_handler.py verificar '${token}'`);
        
        if (stderr) {
            console.error('Error en Python (stderr):', stderr);
            throw new Error(stderr);
        }
        
        return JSON.parse(stdout); // El resultado viene como JSON
    } catch (error) {
        console.error('Error al verificar token:', error);
        return { valido: false, error: 'Error al verificar token' };
    }
}

// ENDPOINT: POST /login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    console.log('=== INTENTO DE LOGIN ===');
    console.log('Email:', email);

    if (!email || !password) {
        return res.status(400).json({ error: "Email y contraseña son requeridos" });
    }

    const sqlSearch = "SELECT * FROM usuarios WHERE email = ?";
    
    db.get(sqlSearch, [email], async (err, user) => {
        if (err) {
            console.error('Error en BD:', err);
            return res.status(500).json({ error: "Error en el servidor" });
        }
        
        if (!user) {
            return res.status(401).json({ error: "Credenciales inválidas" });
        }

        try {
            const match = await bcrypt.compare(password, user.password);
            
            if (match) {
                console.log('Login exitoso, generando token...');
                
                const payload = {
                    user_id: user.id,
                    email: user.email,
                    role: user.role || 'user'
                };
                
                try {
                    const token = await generarJWT(payload);
                    
                    console.log('Token generado correctamente');
                    
                    res.status(200).json({ 
                        message: "Login exitoso",
                        token: token,
                        email: user.email,
                        role: user.role 
                    });
                    
                } catch (jwtError) {
                    console.error('ERROR generando JWT:', jwtError);
                    res.status(500).json({ 
                        error: "Error al generar token de autenticación",
                        detalle: jwtError.message 
                    });
                }
            } else {
                res.status(401).json({ error: "Credenciales inválidas" });
            }
        } catch (error) {
            console.error('Error en bcrypt:', error);
            res.status(500).json({ error: "Error al verificar la contraseña" });
        }
    });
});


// ENDPOINT: POST /registro
app.post('/registro', async (req, res) => {
    const { email, password } = req.body;

    // 1. Validar datos de entrada (Password mayor a 8 y menor a 10)
    if (!email || !password || password.length <= 8 || password.length >= 10) {
        return res.status(400).send("Error 400: Credenciales Invalidas");
    }
    // Validar formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).send("Error 400: Formato de email inválido");
    }

    // 2. Verificar duplicados (Email existente)
    const sqlCheck = `SELECT * FROM usuarios WHERE email = ?`;
    
    db.get(sqlCheck, [email], async (err, row) => {
        if (err) return res.status(500).send("Error en el servidor");
        
        if (row) {
            return res.status(409).send("ERROR 409: El usuario ya existe");
        }

        // 3. Si no es duplicado, cifrar la contraseña con bcrypt
        try {
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // 4. Guardar en la base de datos
            const sqlInsert = `INSERT INTO usuarios (email, password) VALUES (?, ?)`;
            
            db.run(sqlInsert, [email, hashedPassword], function(err) {
                if (err) return res.status(500).send("Error al guardar usuario");
                
                // 5. Éxito
                res.status(201).send("Success 201: Usuario Registrado");
            });

        } catch (error) {
            res.status(500).send("Error al cifrar contraseña");
        }
    });
});

// ENDPOINT PUT /cambiar-rol/:email
app.put('/cambiar-rol/:email', (req, res) => {
    //Obtenemos el email de la URL y el nuevo rol del cuerpo
    const userEmail = req.params.email;
    const { newRole } = req.body;

    //Validación básica
    if (!newRole) {
        return res.status(400).json({ error: "Debes proporcionar el nuevo rol (newRole)." });
    }

    //Primero verificamos si el usuario existe
    const sqlSearch = "SELECT * FROM usuarios WHERE email = ?";

    db.get(sqlSearch, [userEmail], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(404).json({ error: "Usuario no encontrado." });

        //SI EXISTE, entonces ejecutamos el UPDATE (dentro del callback)
        const sqlUpdate = "UPDATE usuarios SET role = ? WHERE email = ?";
        
        db.run(sqlUpdate, [newRole, userEmail], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
            res.status(200).json({ 
                message: `Rol de ${userEmail} actualizado a ${newRole}.`,
                cambios: this.changes 
            });
        });
    });
});

//ENDPOINT PUT /cambiar-password
app.put('/usuarios/cambiar-password/:email', (req, res) => {
    
    // Extraemos el email de los parámetros
    const userEmail = req.params.email;
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
        return res.status(400).json({ error: "Datos incompletos." });
    }

    // Buscamos por EMAIL en la base de datos
    const sqlSearch = "SELECT password FROM usuarios WHERE email = ?";
    
    db.get(sqlSearch, [userEmail], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(404).json({ error: "Usuario no encontrado con ese correo." });

        try {
            const match = await bcrypt.compare(oldPassword, user.password);
            
            if (!match) {
                return res.status(401).json({ error: "La contraseña antigua no coincide." });
            }

            const saltRounds = 10;
            const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

            //Actualizamos usando el EMAIL como condición
            const sqlUpdate = "UPDATE usuarios SET password = ? WHERE email = ?";
            db.run(sqlUpdate, [hashedNewPassword, userEmail], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                
                res.status(200).json({ 
                    message: `Contraseña de ${userEmail} actualizada.`,
                    cambios: this.changes 
                });
            });

        } catch (error) {
            res.status(500).json({ error: "Error en el proceso de cifrado." });
        }
    });
});

// Middleware para verificar el JWT en rutas protegidas 
function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 

    if (!token) {
        return res.status(401).json({ error: 'Acceso denegado. Token requerido.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.usuario = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Token inválido o expirado.' });
    }
}

// ENDPOINT POST /comprar
app.post('/comprar', verificarToken, (req, res) => {
    const { producto_id, cantidad } = req.body;
    const usuario_id = req.usuario.user_id;

    // Validación: campos requeridos
    if (producto_id === undefined || cantidad === undefined) {
        return res.status(400).json({ error: "producto_id y cantidad son requeridos." });
    }

    // Validación: producto_id debe ser entero positivo
    if (!Number.isInteger(producto_id) || producto_id <= 0) {
        return res.status(400).json({ error: "producto_id debe ser un número entero positivo." });
    }

    // Validación: cantidad debe ser entero positivo (no negativa, no cero)
    if (!Number.isInteger(cantidad) || cantidad <= 0) {
        return res.status(400).json({ error: "La cantidad debe ser un número entero positivo." });
    }

    // Buscar el producto en la BD para obtener precio y verificar stock (Anti-SQLi)
    const sqlProducto = "SELECT * FROM productos WHERE id = ?";
    db.get(sqlProducto, [producto_id], (err, producto) => {
        if (err) return res.status(500).json({ error: "Error en el servidor." });
        if (!producto) return res.status(404).json({ error: "Producto no encontrado." });

        // Verificar stock suficiente
        if (producto.stock < cantidad) {
            return res.status(400).json({ 
                error: "Stock insuficiente.",
                stock_disponible: producto.stock
            });
        }

        const total = producto.precio * cantidad;

        // Registrar la compra — consulta parametrizada (Anti-SQLi)
        const sqlInsert = `
            INSERT INTO compras (usuario_id, producto_id, cantidad, total, fecha)
            VALUES (?, ?, ?, ?, datetime('now'))
        `;
        db.run(sqlInsert, [usuario_id, producto_id, cantidad, total], function(err) {
            if (err) return res.status(500).json({ error: "Error al registrar la compra." });

            const compra_id = this.lastID;

            // Descontar stock — consulta parametrizada (Anti-SQLi)
            const sqlStock = "UPDATE productos SET stock = stock - ? WHERE id = ?";
            db.run(sqlStock, [cantidad, producto_id], (err) => {
                if (err) return res.status(500).json({ error: "Error al actualizar stock." });

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
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
    console.log(`Listo para recibir peticiones POST en /registro`);
});