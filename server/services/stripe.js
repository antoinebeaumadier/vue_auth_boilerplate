const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

class StripeService {
    constructor() {
        this.MIN_AMOUNT = 50; // Minimum amount in cents
        this.SUPPORTED_CURRENCIES = ['eur', 'usd', 'gbp'];
        this.idempotencyKeys = new Set(); // Track used idempotency keys
    }

    validateAmount(amount) {
        if (typeof amount !== 'number' || amount < this.MIN_AMOUNT) {
            throw new Error(`Amount must be at least ${this.MIN_AMOUNT} cents`);
        }
        return true;
    }

    validateCurrency(currency) {
        if (!this.SUPPORTED_CURRENCIES.includes(currency.toLowerCase())) {
            throw new Error(`Unsupported currency. Supported currencies are: ${this.SUPPORTED_CURRENCIES.join(', ')}`);
        }
        return true;
    }

    async createPaymentIntent(amount, currency = 'eur', metadata = {}, idempotencyKey) {
        try {
            this.validateAmount(amount);
            this.validateCurrency(currency);

            // Check if this idempotency key was already used
            if (this.idempotencyKeys.has(idempotencyKey)) {
                throw new Error('Duplicate request detected');
            }

            const paymentIntent = await stripe.paymentIntents.create({
                amount,
                currency,
                automatic_payment_methods: {
                    enabled: true,
                },
                metadata
            }, {
                idempotencyKey
            });

            // Store the idempotency key
            this.idempotencyKeys.add(idempotencyKey);

            console.log(`Created payment intent: ${paymentIntent.id} with idempotency key: ${idempotencyKey}`);
            return paymentIntent;
        } catch (error) {
            console.error('Error creating payment intent:', error);
            throw new Error(`Error creating payment intent: ${error.message}`);
        }
    }

    async handleWebhook(payload, signature) {
        try {
            const event = stripe.webhooks.constructEvent(
                payload,
                signature,
                process.env.STRIPE_WEBHOOK_SECRET
            );

            console.log(`Received webhook event: ${event.type}`);

            // Check for duplicate events using idempotency
            const eventId = event.id;
            const existingEvent = await prisma.webhookEvent.findUnique({
                where: { stripeEventId: eventId }
            });

            if (existingEvent) {
                console.log(`Duplicate webhook event detected: ${eventId}`);
                return event;
            }

            // Store the event ID to prevent duplicate processing
            await prisma.webhookEvent.create({
                data: { stripeEventId: eventId }
            });

            switch (event.type) {
                case 'payment_intent.succeeded':
                    await this.handlePaymentSuccess(event.data.object);
                    break;
                case 'payment_intent.payment_failed':
                    await this.handlePaymentFailure(event.data.object);
                    break;
                case 'charge.refunded':
                    await this.handleRefund(event.data.object);
                    break;
                case 'customer.subscription.created':
                case 'customer.subscription.updated':
                case 'customer.subscription.deleted':
                    await this.handleSubscriptionEvent(event);
                    break;
                default:
                    console.log(`Unhandled event type: ${event.type}`);
            }

            return event;
        } catch (error) {
            console.error('Webhook Error:', error);
            throw new Error(`Webhook Error: ${error.message}`);
        }
    }

    async handlePaymentSuccess(paymentIntent) {
        try {
            // Update your database with the successful payment
            await prisma.payment.create({
                data: {
                    stripePaymentId: paymentIntent.id,
                    amount: paymentIntent.amount,
                    currency: paymentIntent.currency,
                    status: 'succeeded',
                    metadata: paymentIntent.metadata
                }
            });
            console.log(`Payment succeeded: ${paymentIntent.id}`);
        } catch (error) {
            console.error('Error handling payment success:', error);
            throw error;
        }
    }

    async handlePaymentFailure(paymentIntent) {
        try {
            // Update your database with the failed payment
            await prisma.payment.create({
                data: {
                    stripePaymentId: paymentIntent.id,
                    amount: paymentIntent.amount,
                    currency: paymentIntent.currency,
                    status: 'failed',
                    metadata: paymentIntent.metadata
                }
            });
            console.log(`Payment failed: ${paymentIntent.id}`);
        } catch (error) {
            console.error('Error handling payment failure:', error);
            throw error;
        }
    }

    async handleRefund(refund) {
        try {
            // Update your database with the refund information
            await prisma.refund.create({
                data: {
                    stripeRefundId: refund.id,
                    paymentId: refund.payment_intent,
                    amount: refund.amount,
                    currency: refund.currency,
                    reason: refund.reason
                }
            });
            console.log(`Refund processed: ${refund.id}`);
        } catch (error) {
            console.error('Error handling refund:', error);
            throw error;
        }
    }

    async handleSubscriptionEvent(event) {
        try {
            const subscription = event.data.object;
            await prisma.subscription.upsert({
                where: { stripeSubscriptionId: subscription.id },
                update: {
                    status: subscription.status,
                    currentPeriodEnd: new Date(subscription.current_period_end * 1000),
                    metadata: subscription.metadata
                },
                create: {
                    stripeSubscriptionId: subscription.id,
                    customerId: subscription.customer,
                    status: subscription.status,
                    currentPeriodEnd: new Date(subscription.current_period_end * 1000),
                    metadata: subscription.metadata
                }
            });
            console.log(`Subscription ${event.type}: ${subscription.id}`);
        } catch (error) {
            console.error('Error handling subscription event:', error);
            throw error;
        }
    }
}

module.exports = new StripeService(); 