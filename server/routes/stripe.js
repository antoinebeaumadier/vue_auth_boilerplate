const express = require('express');
const router = express.Router();
const stripeService = require('../services/stripe');
const { authenticateUser } = require('../middleware/auth');
const { rateLimiters } = require('../middleware/security');
const { v4: uuidv4 } = require('uuid');

// Create a payment intent
router.post('/create-payment-intent', [authenticateUser, rateLimiters.sensitive], async (req, res) => {
    try {
        const { amount, currency, metadata, idempotencyKey } = req.body;
        
        if (!amount) {
            return res.status(400).json({ error: 'Amount is required' });
        }

        // Generate idempotency key if not provided
        const key = idempotencyKey || uuidv4();

        const paymentIntent = await stripeService.createPaymentIntent(
            amount,
            currency,
            { ...metadata, userId: req.user.id },
            key
        );
        
        res.json({ 
            clientSecret: paymentIntent.client_secret,
            paymentIntentId: paymentIntent.id,
            idempotencyKey: key
        });
    } catch (error) {
        console.error('Payment intent creation error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Handle Stripe webhooks
router.post('/webhook', [express.raw({type: 'application/json'}), rateLimiters.standard], async (req, res) => {
    const signature = req.headers['stripe-signature'];
    
    if (!signature) {
        return res.status(400).json({ error: 'Missing stripe-signature header' });
    }
    
    try {
        await stripeService.handleWebhook(req.body, signature);
        res.json({ received: true });
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Get payment status
router.get('/payment/:paymentIntentId', [authenticateUser, rateLimiters.standard], async (req, res) => {
    try {
        const paymentIntent = await stripe.paymentIntents.retrieve(req.params.paymentIntentId);
        
        // Verify the payment belongs to the authenticated user
        if (paymentIntent.metadata.userId !== req.user.id) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        res.json({
            status: paymentIntent.status,
            amount: paymentIntent.amount,
            currency: paymentIntent.currency,
            created: paymentIntent.created
        });
    } catch (error) {
        console.error('Payment status error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Create a refund
router.post('/refund', [authenticateUser, rateLimiters.sensitive], async (req, res) => {
    try {
        const { paymentIntentId, reason, idempotencyKey } = req.body;
        
        if (!paymentIntentId) {
            return res.status(400).json({ error: 'Payment intent ID is required' });
        }
        
        // Generate idempotency key if not provided
        const key = idempotencyKey || uuidv4();
        
        const refund = await stripe.refunds.create({
            payment_intent: paymentIntentId,
            reason: reason || 'requested_by_customer'
        }, {
            idempotencyKey: key
        });
        
        res.json({
            refundId: refund.id,
            status: refund.status,
            amount: refund.amount,
            idempotencyKey: key
        });
    } catch (error) {
        console.error('Refund error:', error);
        res.status(400).json({ error: error.message });
    }
});

module.exports = router; 