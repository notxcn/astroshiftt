const { DataTypes } = require('sequelize');
const sequelize = require('../database');

const AuthCode = sequelize.define('AuthCode', {
    email: {
        type: DataTypes.STRING,
        primaryKey: true
    },
    code: {
        type: DataTypes.STRING,
        allowNull: false
    },
    expires: {
        type: DataTypes.DATE,
        allowNull: false
    },
    attempts: {
        type: DataTypes.INTEGER,
        defaultValue: 0
    },
    rateLimit: {
        type: DataTypes.DATE
    }
});

module.exports = AuthCode;
