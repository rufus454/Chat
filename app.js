const express = require('express');
const cors = require('cors');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const routeConfig = require('./routes/routes.js');
const fs = require('fs');
const http = require('http');
const PORT = process.env.PORT || 3003;
const app = express();
const socketIO = require('socket.io');
const server = http.createServer(app);
const io = socketIO(server);

// Configuración de CORS para permitir solicitudes desde dominios específicos
const allowedOrigins = ['https://manejador.azurewebsites.net', 'http://dhoubuntu.fullstack.com.mx', 'http://localhost:3003','https://manejador.azurewebsites.net:3003'];
const corsOptions = {
    origin: allowedOrigins
};
app.use(cors(corsOptions));

// Middleware para manejar solicitudes POST y PUT
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware para analizar datos del formulario
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware to serve static files
app.use(express.static(path.join(__dirname, './public')));

// Configuración de express-session
app.use(session({
    secret: 'Lainod', // Cambiar a una cadena aleatoria y segura
    resave: false,
    saveUninitialized: true
}));

// Configurar rutas
routeConfig(app);

// Handling not found routes
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, './public', '404.html'));
});

//Esto es para las cookies de terceros
app.use((req, res, next) => {
    res.cookie('mycookie', 'value', { sameSite: 'None', secure: true });
    next();
  });




// Iniciar el servidor HTTP
server.listen(PORT, () => {
    console.log(`Server running at https://manejador.azurewebsites.net:${PORT}/`);
});

module.exports = app; // Exportar app para uso en otros archivos
