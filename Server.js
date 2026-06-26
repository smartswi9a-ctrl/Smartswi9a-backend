// server.js - Backend complet pour Smart Swi9a

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const emailjs = require('@emailjs/nodejs');

const app = express();
app.use(cors());
app.use(express.json());

// Connexion MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connecté'))
  .catch(err => console.error('❌ Erreur MongoDB :', err));

// --- MODÈLES ---

// Utilisateur
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  favorites: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  addresses: [{
    name: String, phone: String, address: String, city: String, cityId: Number, isDefault: Boolean
  }],
  points: { type: Number, default: 0 },
  notifications: [{
    message: String, read: { type: Boolean, default: false }, date: { type: Date, default: Date.now }
  }],
  resetToken: String,
  resetTokenExpires: Date,
  orders: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Order' }]
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Produit
const productSchema = new mongoose.Schema({
  id: { type: Number, required: true, unique: true },
  category: String,
  stock: { type: Number, default: 0 },
  nameAr: String, nameFr: String, nameEn: String,
  descAr: String, descFr: String, descEn: String,
  featuresAr: [String], featuresFr: [String], featuresEn: [String],
  price: Number, oldPrice: Number,
  img: String, gallery: [String]
}, { timestamps: true });

const Product = mongoose.model('Product', productSchema);

// Commande
const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    quantity: Number
  }],
  status: {
    type: String,
    enum: ['pending', 'shipped', 'delivered', 'received', 'disputed', 'cancelled'],
    default: 'pending'
  },
  receivedDate: Date,
  dispute: {
    explanation: String, photos: [String], openedAt: Date, status: { type: String, enum: ['open', 'closed'] }
  },
  deliveryAddress: {
    name: String, phone: String, address: String, city: String, cityId: Number
  },
  pointsEarned: { type: Number, default: 0 },
  paymentStatus: { type: String, enum: ['unpaid', 'paid'], default: 'unpaid' },
  paymentMethod: { type: String, default: 'Cash' }
}, { timestamps: true });

const Order = mongoose.model('Order', orderSchema);

// --- ROUTES AUTH ---

// Inscription
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email déjà utilisé' });

    const user = new User({ name, email, password });
    await user.save();

    // Générer OTP (simulation)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    // Envoyer via EmailJS
    await emailjs.send(
      process.env.EMAILJS_SERVICE_ID,
      process.env.EMAILJS_TEMPLATE_OTP,
      { email, name, passcode: otp },
      { publicKey: process.env.EMAILJS_USER_ID }
    );

    res.status(201).json({ message: 'Compte créé. Vérifiez votre email pour le code OTP.' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Connexion
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await user.comparePassword(password))) {
    return res.status(401).json({ message: 'Email ou mot de passe incorrect' });
  }
  if (!user.isVerified) {
    return res.status(401).json({ message: 'Compte non vérifié' });
  }
  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
  res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
});

// Middleware d'authentification
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Accès refusé' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token invalide' });
  }
};

// Récupérer l'utilisateur connecté
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId).select('-password');
  res.json({ user });
});

// --- ROUTES PRODUITS ---

// Tous les produits
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Mise à jour stock (admin)
app.post('/api/products/update-stock', authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId);
  if (user.email !== 'admin@smartswi9a.com') return res.status(403).json({ message: 'Accès réservé à l\'admin' });
  const { productId, quantity } = req.body;
  await Product.updateOne({ id: productId }, { $inc: { stock: -quantity } });
  res.json({ message: 'Stock mis à jour' });
});

// --- ROUTES COMMANDES ---

// Créer une commande
app.post('/api/orders', authMiddleware, async (req, res) => {
  const { items, addressId } = req.body;
  const user = await User.findById(req.userId);
  if (!user) return res.status(404).json({ message: 'Utilisateur introuvable' });

  let deliveryAddress = null;
  if (addressId) {
    const addr = user.addresses.id(addressId);
    if (addr) deliveryAddress = addr;
  }

  const order = new Order({
    user: req.userId,
    items: items.map(item => ({ product: item.productId, quantity: item.quantity })),
    deliveryAddress: deliveryAddress
  });

  let total = 0;
  for (let item of items) {
    const product = await Product.findOne({ id: item.productId });
    if (product) {
      total += product.price * item.quantity;
      product.stock = Math.max(0, product.stock - item.quantity);
      await product.save();
    }
  }
  const points = Math.floor(total / 10);
  user.points += points;
  order.pointsEarned = points;
  await order.save();
  user.orders.push(order._id);
  await user.save();

  res.status(201).json({ order, pointsEarned: points });
});

// Obtenir les commandes de l'utilisateur
app.get('/api/orders', authMiddleware, async (req, res) => {
  const orders = await Order.find({ user: req.userId }).populate('items.product');
  res.json(orders);
});

// Confirmer réception
app.post('/api/orders/:orderId/confirm', authMiddleware, async (req, res) => {
  const order = await Order.findOne({ _id: req.params.orderId, user: req.userId });
  if (!order || order.status !== 'pending') return res.status(400).json({ message: 'Commande non trouvée ou déjà confirmée' });
  order.status = 'received';
  order.receivedDate = new Date();
  await order.save();
  res.json({ message: 'Réception confirmée' });
});

// --- ROUTES FAVORIS ---

// Ajouter/retirer des favoris
app.post('/api/favorites/:productId', authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId);
  const productId = req.params.productId;
  const idx = user.favorites.indexOf(productId);
  if (idx !== -1) {
    user.favorites.splice(idx, 1);
    await user.save();
    res.json({ message: 'Retiré des favoris' });
  } else {
    user.favorites.push(productId);
    await user.save();
    res.json({ message: 'Ajouté aux favoris' });
  }
});

// --- ROUTES AVIS (à implémenter si besoin) ---

// --- IMPORT PRODUITS (une seule fois) ---
app.post('/api/products/import', async (req, res) => {
  const { secret } = req.body;
  if (secret !== 'import123') return res.status(403).json({ message: 'Secret invalide' });
  try {
    const fs = require('fs');
    const path = require('path');
    const data = JSON.parse(fs.readFileSync(path.join(__dirname, 'produits.json'), 'utf8'));
    await Product.deleteMany();
    await Product.insertMany(data);
    res.json({ message: 'Produits importés' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// --- DÉMARRAGE ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Serveur lancé sur port ${PORT}`));
