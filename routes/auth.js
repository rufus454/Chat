const jwt = require('jsonwebtoken');
const secretKey = 'Lainod'; // Clave secreta para firmar los tokens

function generarToken(payload) {
   // console.log("Clave secreta utilizada para firmar el token:", secretKey); // Imprime la clave secreta utilizada
    return jwt.sign(payload, secretKey, { expiresIn: '3h' }); // Genera un token con un tiempo de expiración de 3 horas
}

// Función para verificar un token JWT
function verificarToken(token) {
   // console.log("Clave secreta utilizada para verificar el token:", secretKey); // Imprime la clave secreta utilizada
    try {
        // Verifica el token usando la clave secreta
        const decoded = jwt.verify(token, secretKey);
        return decoded;
    } catch (error) {
        console.error('Error al verificar el token:', error);
        return null; // Devuelve null si hay un error al verificar el token
    }
}

module.exports = { generarToken, verificarToken };
