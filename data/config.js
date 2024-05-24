require('dotenv').config(); // Cargar variables de entorno desde .env
const mysql = require('mysql2');

// create a MySQL pool
const pool = mysql.createPool({
  host: process.env.H,
  user: process.env.U,
  password: process.env.P,
  database: process.env.DB,
  ssl: {
 //   ca: require('fs').readFileSync(process.env.SSL_CA),
//    key: require('fs').readFileSync(process.env.SSL_KEY),
//    cert: require('fs').readFileSync(process.env.SSL_CERT),
    rejectUnauthorized: false
  }
});

pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error connecting to database: ', err);
    } else {
      console.log('Connected to database successfully!');
      // Release the connection
      connection.release();
    }
});

module.exports = pool;
