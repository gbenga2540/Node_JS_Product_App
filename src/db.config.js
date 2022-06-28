const mysql = require('mysql');
require('dotenv').config();

const connection = mysql.createConnection({
    host: process.env.NODE_HOST,
    user: process.env.NODE_DB_USER,
    password: process.env.NODE_DB_PASSWORD,
    database: process.env.NODE_DB_DATABASE
});
connection.connect((err) => {
    if (err) throw err;
    console.log('SQL Database Connected!!!');
});

module.exports = connection;