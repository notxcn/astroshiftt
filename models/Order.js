const { DataTypes } = require('sequelize');
const sequelize = require('../database');

const Order = sequelize.define('Order', {
    id: {
        type: DataTypes.STRING,
        primaryKey: true
    },
    type: {
        type: DataTypes.STRING,
        allowNull: false
    },
    status: {
        type: DataTypes.STRING,
        defaultValue: 'pending'
    },
    fromCcy: {
        type: DataTypes.STRING,
        allowNull: false
    },
    toCcy: {
        type: DataTypes.STRING,
        allowNull: false
    },
    fromAmount: {
        type: DataTypes.FLOAT,
        allowNull: false
    },
    toAmount: {
        type: DataTypes.FLOAT
    },
    toAddress: {
        type: DataTypes.STRING,
        allowNull: false
    },
    paymentMethod: {
        type: DataTypes.STRING
    },
    paymentInfo: {
        type: DataTypes.JSON
    },
    transactionId: {
        type: DataTypes.STRING
    },
    ffOrderId: {
        type: DataTypes.STRING
    },
    ffDepositAddress: {
        type: DataTypes.STRING
    },
    email: {
        type: DataTypes.STRING
    },
    adminNotes: {
        type: DataTypes.TEXT
    },
    expiresAt: {
        type: DataTypes.DATE
    },
    paymentSubmittedAt: {
        type: DataTypes.DATE
    }
});

module.exports = Order;
