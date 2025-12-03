const { Order } = require('./models');
const { v4: uuidv4 } = require('uuid');
const sequelize = require('./database');

async function testPersistence() {
    try {
        await sequelize.sync();

        // 1. Create an order
        const orderId = uuidv4();
        console.log(`Creating order ${orderId}...`);
        await Order.create({
            id: orderId,
            type: 'fiat-to-crypto',
            status: 'pending',
            fromCcy: 'USD',
            toCcy: 'BTC',
            fromAmount: 100,
            toAmount: 0.002,
            toAddress: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
            email: 'test@example.com'
        });
        console.log('Order created.');

        // 2. Verify it exists
        const order = await Order.findByPk(orderId);
        if (order) {
            console.log('✅ Order found in DB immediately.');
        } else {
            console.error('❌ Order NOT found in DB immediately.');
        }

        // 3. Simulate "restart" (just query again, as the DB file persists)
        console.log('Verifying persistence...');
        const orderPersistent = await Order.findByPk(orderId);
        if (orderPersistent) {
            console.log('✅ Order persists in DB.');
        } else {
            console.error('❌ Order LOST from DB.');
        }

    } catch (error) {
        console.error('Test failed:', error);
    } finally {
        await sequelize.close();
    }
}

testPersistence();
