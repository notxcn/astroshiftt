const { DataTypes } = require('sequelize');
const sequelize = require('../database');

const Session = sequelize.define('Session', {
    token: {
        type: DataTypes.STRING,
        primaryKey: true
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false
    },
    expires: {
        type: DataTypes.DATE,
        allowNull: false
    }
});

module.exports = Session;
