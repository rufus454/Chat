// Importa bcryptjs y express-session
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const pool = require('../data/config');
const jwt = require('jsonwebtoken');
const secretKey = 'Lainod'; // Clave secreta para firmar los tokens
const { generarToken, verificarToken } = require('./auth'); // Importar funciones de autenticación

const router = (app) => {
    // Ruta de la aplicación
    // Mostrar mensaje de bienvenida en la ruta raíz
    app.get('/api/', (request, response) => {
        response.json({ message: '¡Bienvenido a Node.js Express REST API!' });
    });
// Ruta para generar el token
app.post('/api/token', (req, res) => {
    try {
      // Suponiendo que req.body contiene los datos del usuario autenticado,
      // y que req.body.id es el ID único del usuario
      const payload = { userId: req.body.id };
      const token = generarToken(payload);
      res.json({ token }); // Devuelve el token como objeto JSON
    } catch (error) {
      console.error('Error al generar el token:', error);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  });

    // Agrega protección con token JWT a la ruta para mostrar un solo usuario por ID
    app.get('/api/users/:id', (request, response) => {
        const id = request.params.id;

        // Verifica el token antes de ejecutar la consulta en la base de datos
        const token = request.headers.authorization;
        const decodedToken = verificarToken(token);

        if (!decodedToken) {
            return response.status(401).json({ error: 'Token inválido' });
        }

        pool.query('SELECT * FROM users WHERE id = ?', id, (error, results) => {
            if (error) {
                console.error('Error al obtener usuarios:', error);
                return response.status(500).json({ error: 'Error interno del servidor' });
            }
            response.json(results);
        });
    });

    // Mostrar todos los Usuarios Token
    app.get('/api/users', (request, response) => {
        const token = request.headers['authorization']; // Obtener el token del encabezado de autorización
        if (!token) {
            return response.status(401).json({ error: 'Token no proporcionado' }); // Si no hay token, devolver un error de no autorizado
        }

        const decodedToken = verificarToken(token); // Verificar el token
        if (!decodedToken) {
            return response.status(401).json({ error: 'Token inválido' }); // Si el token no es válido, devolver un error de no autorizado
        }

        // Si el token es válido, proceder con la consulta a la base de datos para mostrar todos los usuarios
        pool.query('SELECT * FROM users', (error, results) => {
            if (error) {
                console.error('Error al obtener usuarios:', error);
                return response.status(500).json({ error: 'Error interno del servidor' });
            }
            response.status(200).json(results); // Enviar los resultados de la consulta como respuesta en formato JSON con el código de estado 200
        });
    });

    // Agregar un nuevo usuario Token
    app.post('/api/users', (request, response) => {
        const userData = request.body;
        const plaintextPassword = userData.contrasea; // Obtén la contraseña sin hashear desde la solicitud

        // Hashea la contraseña antes de almacenarla en la base de datos
        bcrypt.hash(plaintextPassword, 10, (err, hash) => {
            if (err) {
                return response.status(500).json({ error: 'Error interno del servidor' });
            }

            // Almacena el usuario en la base de datos con la contraseña hasheada
            pool.query('INSERT INTO users (nombre, contrasea) VALUES (?, ?)', [userData.nombre, hash], (error, result) => {
                if (error) {
                    console.error('Error al agregar un nuevo usuario:', error);
                    return response.status(500).json({ error: 'Error interno del servidor' });
                }
                console.log('Usuario agregado con éxito');
                response.status(201).send(`Usuario agregado con ID: ${result.insertId}`);
            });
        });
    });

    // Actualizar un usuario Token
    app.put('/api/users/:id', (request, response) => {
        const token = request.headers['authorization']; // Obtener el token del encabezado de autorización
        if (!token) {
            return response.status(401).json({ error: 'Token no proporcionado' }); // Si no hay token, devolver un error de no autorizado
        }

        const decodedToken = verificarToken(token); // Verificar el token
        if (!decodedToken) {
            return response.status(401).json({ error: 'Token inválido' }); // Si el token no es válido, devolver un error de no autorizado
        }

        const id = request.params.id;
        const userData = request.body;
        const plaintextPassword = userData.contrasea; // Obtén la nueva contraseña sin hashear desde la solicitud

        // Hashea la nueva contraseña antes de actualizarla en la base de datos
        bcrypt.hash(plaintextPassword, 10, (err, hash) => {
            if (err) {
                console.error('Error al hashear la contraseña:', err);
                return response.status(500).json({ error: 'Error interno del servidor' });
            }

            // Actualiza el usuario en la base de datos con la contraseña hasheada
            pool.query('UPDATE users SET nombre = ?, contrasea = ? WHERE id = ?', [userData.nombre, hash, id], (error, result) => {
                if (error) {
                    console.error('Error al actualizar el usuario:', error);
                    return response.status(500).json({ error: 'Error interno del servidor' });
                }
                console.log('Usuario actualizado con éxito');
                response.send("Usuario actualizado correctamente");
            });
        });
    });

    // Borrar un Usuario Token
    app.delete('/api/users/:id', (request, response) => {
        const token = request.headers['authorization']; // Obtener el token del encabezado de autorización
        if (!token) {
            return response.status(401).json({ error: 'Token no proporcionado' }); // Si no hay token, devolver un error de no autorizado
        }

        const decodedToken = verificarToken(token); // Verificar el token
        if (!decodedToken) {
            return response.status(401).json({ error: 'Token inválido' }); // Si el token no es válido, devolver un error de no autorizado
        }

        const id = request.params.id;

        pool.query('DELETE FROM users WHERE id = ?', [id], (error, result) => {
            if (error) {
                console.error('Error al eliminar el usuario:', error);
                return response.status(500).json({ error: 'Error interno del servidor' });
            }
            console.log('Usuario eliminado con éxito');
            response.send("Usuario eliminado correctamente");
        });
    });

    // Ruta para iniciar sesión y generar un token JWT
    app.post('/api/login', (req, res) => {
        const { username, password } = req.body;

        pool.query('SELECT * FROM users WHERE nombre = ?', [username], (err, results) => {
            if (err) {
                console.error('Error al buscar usuario en la base de datos:', err);
                return res.status(500).send('Error interno del servidor');
            }

            if (results.length === 0) {
                return res.status(401).send('Credenciales inválidas');
            }

            const user = results[0];

            bcrypt.compare(password, user.contrasea, (err, result) => {
                if (err) {
                    console.error('Error al comparar contraseñas:', err);
                    return res.status(500).send('Error interno del servidor');
                }

                if (result) {
                    // Generar token JWT al iniciar sesión exitosamente
                    const payload = { username: username };
                    const token = jwt.sign(payload, secretKey, { expiresIn: '3h' }); // Genera el token con un tiempo de expiración de 3 horas
                    res.send({ token: token });
                } else {
                    res.status(401).send('Credenciales inválidas');
                }
            });
        });
    });

    // Resetear contraseña
    app.post('/api/login/reset-password/:id', (request, response) => {
        const id = request.params.id;
        const newPassword = request.body.newPassword;

        // Hashea la nueva contraseña antes de almacenarla en la base de datos
        bcrypt.hash(newPassword, 10, (err, hash) => {
            if (err) {
                console.error('Error al hashear la contraseña:', err);
                return response.status(500).send('Error interno del servidor');
            }

            // Actualiza la contraseña del usuario en la base de datos con la contraseña hasheada
            pool.query('UPDATE users SET contrasea = ? WHERE id = ?', [hash, id], (error, result) => {
                if (error) {
                    console.error('Error al actualizar la contraseña del usuario:', error);
                    return response.status(500).send('Error interno del servidor');
                }
                console.log('Contraseña del usuario actualizada con éxito');
                response.send("Contraseña del usuario actualizada correctamente");
            });
        });
    });

    // Definir la ruta para confirmar la contraseña antes de editar un usuario
    app.post('/api/users/confirm-password/:id', (req, res) => {
        const token = req.headers['authorization']; // Obtener el token del encabezado de autorización
        if (!token) {
            return res.status(401).json({ error: 'Token no proporcionado' }); // Si no hay token, devolver un error de no autorizado
        }

        const decodedToken = verificarToken(token); // Verificar el token
        if (!decodedToken) {
            return res.status(401).json({ error: 'Token inválido' }); // Si el token no es válido, devolver un error de no autorizado
        }

        const userId = req.params.id;
        const enteredPassword = req.body.password;

        // Verificar la contraseña ingresada con la contraseña almacenada en la base de datos
        pool.query('SELECT contrasea FROM users WHERE id = ?', userId, (err, results) => {
            if (err) {
                console.error('Error al buscar contraseña en la base de datos:', err);
                return res.status(500).send('Error interno del servidor');
            }

            if (results.length === 0) {
                return res.status(404).send('Usuario no encontrado');
            }

            const storedPasswordHash = results[0].contrasea;

            // Compara la contraseña ingresada con la contraseña almacenada
            bcrypt.compare(enteredPassword, storedPasswordHash, (err, result) => {
                if (err) {
                    console.error('Error al comparar contraseñas:', err);
                    return res.status(500).send('Error interno del servidor');
                }

                if (result) {
                    // Si la contraseña es correcta, enviar una respuesta exitosa
                    return res.status(200).send('Contraseña correcta');
                } else {
                    // Si la contraseña es incorrecta, enviar un mensaje de error
                    return res.status(401).send('Contraseña incorrecta');
                }
            });
        });
    });

    //---------------------------------------------------------------------------------------------------

    // Agregar un nuevo usuario Token con tres contraseñas haseadas
    // Funciones para generar hashes MD5, SHA256 y SHA1
    function generateMD5Hash(password) {
        return crypto.createHash('md5').update(password).digest('hex');
    }

    function generateSHA256Hash(password) {
        return crypto.createHash('sha256').update(password).digest('hex');
    }

    function generateSHA1Hash(password) {
        return crypto.createHash('sha1').update(password).digest('hex');
    }
    // Agregar un nuevo usuario con contraseña hasheada en diferentes formatos
    app.post('/api/users/hashs', (request, response) => {
        const token = request.headers['authorization'];
        if (!token) {const request = require('supertest');
        const app = require('./app');
        
        describe('Pruebas de la API', () => {
          // Prueba para la ruta POST /token
          it('debería generar un token JWT', async () => {
            const response = await request(app)
              .post('/token')
              .send({ id: 1 }); // Reemplaza con los datos del usuario autenticado
            expect(response.statusCode).toBe(200);
            expect(response.text).toContain('Token generado:');
          });
        
          // Prueba para la ruta GET /users
          it('debería devolver todos los usuarios', async () => {
            const response = await request(app)
              .get('/users')
              .set('Authorization', 'Bearer tuTokenJWT'); // Reemplaza 'tuTokenJWT' con un token JWT válido
            expect(response.statusCode).toBe(200);
            expect(response.body).toBeDefined(); // Verificar que se devuelvan usuarios
          });
        
          // Prueba para la ruta POST /users
          it('debería agregar un nuevo usuario', async () => {
            const newUser = { nombre: 'NuevoUsuario', contrasea: 'nuevaContraseña' }; // Reemplaza con los datos del nuevo usuario
            const response = await request(app)
              .post('/users')
              .set('Authorization', 'Bearer tuTokenJWT') // Reemplaza 'tuTokenJWT' con un token JWT válido
              .send(newUser);
            expect(response.statusCode).toBe(201);
            expect(response.text).toContain('Usuario agregado con ID:');
          });
        
          // Prueba para la ruta PUT /users/:id
          it('debería actualizar un usuario por su ID', async () => {
            const updatedUser = { nombre: 'UsuarioActualizado', contrasea: 'nuevaContraseña' }; // Reemplaza con los datos actualizados del usuario
            const response = await request(app)
              .put('/users/1') // Reemplaza '1' con el ID del usuario que quieres actualizar
              .set('Authorization', 'Bearer tuTokenJWT') // Reemplaza 'tuTokenJWT' con un token JWT válido
              .send(updatedUser);
            expect(response.statusCode).toBe(200);
            expect(response.text).toContain('Usuario actualizado correctamente');
          });
        
          // Prueba para la ruta POST /login
          it('debería iniciar sesión y devolver un token JWT', async () => {
            const credentials = { username: 'usuario', password: 'contraseña' }; // Reemplaza con las credenciales válidas
            const response = await request(app)
              .post('/login')
              .send(credentials);
            expect(response.statusCode).toBe(200);
            expect(response.body).toHaveProperty('token');
          });
        
          // Puedes agregar más pruebas según sea necesario para otras rutas y funcionalidades
        });
        
            return response.status(401).json({ error: 'Token no proporcionado' });
        }

        const decodedToken = verificarToken(token);
        if (!decodedToken) {
            return response.status(401).json({ error: 'Token inválido' });
        }

        const userData = request.body;
        const plaintextPassword = userData.contrasea;

        bcrypt.hash(plaintextPassword, 10, (err, bcryptHash) => {
            if (err) {
                console.error('Error al hashear la contraseña:', err);
                return response.status(500).json({ error: 'Error interno del servidor' });
            }

            pool.query('INSERT INTO users (nombre, contrasea, md5_hash, sha256_hash, sha1_hash) VALUES (?, ?, ?, ?, ?)',
                [userData.nombre, bcryptHash, generateMD5Hash(plaintextPassword), generateSHA256Hash(plaintextPassword), generateSHA1Hash(plaintextPassword)],
                (error, result) => {
                    if (error) {
                        console.error('Error al agregar un nuevo usuario:', error);
                        return response.status(500).json({ error: 'Error interno del servidor' });
                    }
                    console.log('Usuario agregado con éxito');
                    response.status(201).send(`Usuario agregado con ID: ${result.insertId}`);
                });
        });
    });
};

// Exportar el Router
module.exports = router;
