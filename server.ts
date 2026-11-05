import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { createServer as createViteServer } from 'vite';
import db, { initializeSchema } from './src/db/database.ts';
import { seedDatabase, FREE_CATEGORIES, PREMIUM_CATEGORIES } from './src/db/seedData.ts';

initializeSchema();
seedDatabase();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'crecisano-dev-secret-key-2026';

// Ensure upload directories exist
const uploadsImagesDir = path.join(process.cwd(), 'uploads', 'images');
const uploadsVideosDir = path.join(process.cwd(), 'uploads', 'videos');
fs.mkdirSync(uploadsImagesDir, { recursive: true });
fs.mkdirSync(uploadsVideosDir, { recursive: true });

app.use(express.json({ limit: '10mb' }));
app.use('/dishes', express.static(path.join(process.cwd(), 'src', 'assets', 'images')));
app.use('/uploads/images', express.static(uploadsImagesDir));
app.use('/uploads/videos', express.static(uploadsVideosDir));

// Multer config for images (JPG, JPEG, PNG, WEBP)
const imageStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsImagesDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `img_${Date.now()}_${crypto.randomBytes(4).toString('hex')}${ext}`);
  },
});

const uploadImage = multer({
  storage: imageStorage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Formato de imagen no válido. Solo se permiten JPG, JPEG, PNG y WEBP.'));
    }
  },
});

// Multer config for optional original videos (MP4, WEBM)
const videoStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsVideosDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `vid_${Date.now()}_${crypto.randomBytes(4).toString('hex')}${ext}`);
  },
});

const uploadVideo = multer({
  storage: videoStorage,
  limits: { fileSize: 80 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['.mp4', '.webm', '.mov'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Formato de video no válido. Solo se permiten MP4, WEBM o MOV.'));
    }
  },
});

interface AuthUser {
  id: number;
  nombre: string;
  correo: string;
  rol: 'usuaria' | 'admin';
  foto_perfil: string | null;
}

interface AuthRequest extends Request {
  user?: AuthUser;
}

function getActiveSubscription(userId: number) {
  // Automatically expire any subscriptions past fecha_vencimiento
  db.prepare(`
    UPDATE suscripciones
    SET estado = 'vencida'
    WHERE usuaria_id = ? AND estado IN ('activa', 'cancelada') AND datetime(fecha_vencimiento) <= datetime('now')
  `).run(userId);

  const sub = db.prepare(`
    SELECT * FROM suscripciones
    WHERE usuaria_id = ? AND estado IN ('activa', 'cancelada') AND datetime(fecha_vencimiento) > datetime('now')
    ORDER BY datetime(fecha_vencimiento) DESC
    LIMIT 1
  `).get(userId) as {
    id: number;
    usuaria_id: number;
    plan: string;
    estado: string;
    fecha_inicio: string;
    fecha_vencimiento: string;
    identificador_transaccion: string;
  } | undefined;

  return sub || null;
}

function optionalAuth(req: AuthRequest, _res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    try {
      const decoded = jwt.verify(token, JWT_SECRET) as { userId: number };
      const user = db.prepare('SELECT id, nombre, correo, rol, foto_perfil FROM usuarios WHERE id = ?').get(decoded.userId) as AuthUser | undefined;
      if (user) {
        req.user = user;
      }
    } catch {
      // Invalid or expired token -> treat as guest
    }
  }
  next();
}

function requireAuth(req: AuthRequest, res: Response, next: NextFunction) {
  optionalAuth(req, res, () => {
    if (!req.user) {
      return res.status(401).json({ error: 'Debes iniciar sesión para realizar esta acción.' });
    }
    next();
  });
}

function requireAdmin(req: AuthRequest, res: Response, next: NextFunction) {
  requireAuth(req, res, () => {
    if (req.user?.rol !== 'admin') {
      return res.status(403).json({ error: 'Acceso restringido solo a cuentas administradoras.' });
    }
    next();
  });
}

function buildUserPayload(user: AuthUser) {
  const subscription = getActiveSubscription(user.id);
  const isPremium = Boolean(subscription) || user.rol === 'admin';
  const favorites = (db.prepare('SELECT receta_id FROM favoritos WHERE usuaria_id = ?').all(user.id) as Array<{ receta_id: number }>).map(f => f.receta_id);
  const prepared = (db.prepare('SELECT receta_id FROM recetas_preparadas WHERE usuaria_id = ?').all(user.id) as Array<{ receta_id: number }>).map(p => p.receta_id);
  const payments = db.prepare('SELECT * FROM pagos WHERE usuaria_id = ? ORDER BY datetime(fecha) DESC').all(user.id);
  const subscriptionHistory = db.prepare('SELECT * FROM suscripciones WHERE usuaria_id = ? ORDER BY datetime(fecha_inicio) DESC').all(user.id);

  return {
    ...user,
    isPremium,
    subscription,
    favorites,
    prepared,
    payments,
    subscriptionHistory,
  };
}

// ==================== AUTH ROUTES ====================
app.post('/api/auth/register', (req: Request, res: Response) => {
  const { nombre, correo, password } = req.body;
  if (!nombre || !correo || !password) {
    return res.status(400).json({ error: 'Por favor completa nombre, correo electrónico y contraseña.' });
  }
  if (String(password).length < 6) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres.' });
  }
  const normalizedEmail = String(correo).trim().toLowerCase();
  const existing = db.prepare('SELECT id FROM usuarios WHERE correo = ?').get(normalizedEmail);
  if (existing) {
    return res.status(409).json({ error: 'Ya existe una cuenta registrada con este correo electrónico.' });
  }

  const hash = bcrypt.hashSync(String(password), 10);
  const result = db.prepare(`
    INSERT INTO usuarios (nombre, correo, password_hash, rol)
    VALUES (?, ?, ?, 'usuaria')
  `).run(String(nombre).trim(), normalizedEmail, hash);

  const user = db.prepare('SELECT id, nombre, correo, rol, foto_perfil FROM usuarios WHERE id = ?').get(result.lastInsertRowid) as AuthUser;
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

  res.status(201).json({
    token,
    user: buildUserPayload(user),
  });
});

app.post('/api/auth/login', (req: Request, res: Response) => {
  const { correo, password } = req.body;
  if (!correo || !password) {
    return res.status(400).json({ error: 'Ingresa tu correo electrónico y contraseña.' });
  }
  const normalizedEmail = String(correo).trim().toLowerCase();
  const row = db.prepare('SELECT * FROM usuarios WHERE correo = ?').get(normalizedEmail) as (AuthUser & { password_hash: string }) | undefined;
  if (!row || !bcrypt.compareSync(String(password), row.password_hash)) {
    return res.status(401).json({ error: 'Correo electrónico o contraseña incorrectos.' });
  }

  const user: AuthUser = {
    id: row.id,
    nombre: row.nombre,
    correo: row.correo,
    rol: row.rol,
    foto_perfil: row.foto_perfil,
  };
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

  res.json({
    token,
    user: buildUserPayload(user),
  });
});

app.post('/api/auth/forgot-password', (req: Request, res: Response) => {
  const { correo } = req.body;
  if (!correo) {
    return res.status(400).json({ error: 'Ingresa tu correo electrónico.' });
  }
  const normalizedEmail = String(correo).trim().toLowerCase();
  const user = db.prepare('SELECT id FROM usuarios WHERE correo = ?').get(normalizedEmail) as { id: number } | undefined;
  if (!user) {
    return res.status(404).json({ error: 'No encontramos una cuenta asociada a ese correo.' });
  }

  const resetToken = crypto.randomBytes(4).toString('hex').toUpperCase();
  const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  db.prepare('UPDATE usuarios SET reset_token = ?, reset_expires = ? WHERE id = ?').run(resetToken, expires, user.id);

  res.json({
    message: 'Código de recuperación generado. Úsalo para establecer tu nueva contraseña.',
    resetCode: resetToken,
  });
});

app.post('/api/auth/reset-password', (req: Request, res: Response) => {
  const { correo, code, newPassword } = req.body;
  if (!correo || !code || !newPassword) {
    return res.status(400).json({ error: 'Completa todos los campos requeridos.' });
  }
  if (String(newPassword).length < 6) {
    return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres.' });
  }
  const normalizedEmail = String(correo).trim().toLowerCase();
  const user = db.prepare('SELECT id, reset_token, reset_expires FROM usuarios WHERE correo = ?').get(normalizedEmail) as {
    id: number;
    reset_token: string | null;
    reset_expires: string | null;
  } | undefined;

  if (!user || !user.reset_token || user.reset_token !== String(code).trim().toUpperCase()) {
    return res.status(400).json({ error: 'Código de recuperación inválido.' });
  }
  if (!user.reset_expires || new Date(user.reset_expires) < new Date()) {
    return res.status(400).json({ error: 'El código de recuperación ha expirado.' });
  }

  const hash = bcrypt.hashSync(String(newPassword), 10);
  db.prepare('UPDATE usuarios SET password_hash = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?').run(hash, user.id);

  res.json({ message: 'Contraseña actualizada correctamente. Ya puedes iniciar sesión.' });
});

app.get('/api/auth/me', requireAuth, (req: AuthRequest, res: Response) => {
  res.json({ user: buildUserPayload(req.user!) });
});

app.put('/api/account/profile', requireAuth, (req: AuthRequest, res: Response) => {
  const { nombre, correo } = req.body;
  if (!nombre || !correo) {
    return res.status(400).json({ error: 'Nombre y correo son obligatorios.' });
  }
  const normalizedEmail = String(correo).trim().toLowerCase();
  const conflict = db.prepare('SELECT id FROM usuarios WHERE correo = ? AND id != ?').get(normalizedEmail, req.user!.id);
  if (conflict) {
    return res.status(409).json({ error: 'Ese correo ya está siendo utilizado por otra cuenta.' });
  }

  db.prepare('UPDATE usuarios SET nombre = ?, correo = ? WHERE id = ?').run(
    String(nombre).trim(),
    normalizedEmail,
    req.user!.id
  );
  const updated = db.prepare('SELECT id, nombre, correo, rol, foto_perfil FROM usuarios WHERE id = ?').get(req.user!.id) as AuthUser;
  res.json({ user: buildUserPayload(updated) });
});

app.post('/api/account/photo', requireAuth, uploadImage.single('photo'), (req: AuthRequest, res: Response) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No se recibió ninguna fotografía.' });
  }
  const photoUrl = `/uploads/images/${req.file.filename}`;
  db.prepare('UPDATE usuarios SET foto_perfil = ? WHERE id = ?').run(photoUrl, req.user!.id);
  const updated = db.prepare('SELECT id, nombre, correo, rol, foto_perfil FROM usuarios WHERE id = ?').get(req.user!.id) as AuthUser;
  res.json({ user: buildUserPayload(updated) });
});

app.post('/api/account/cancel-subscription', requireAuth, (req: AuthRequest, res: Response) => {
  const sub = getActiveSubscription(req.user!.id);
  if (!sub) {
    return res.status(400).json({ error: 'No tienes una suscripción activa.' });
  }
  db.prepare("UPDATE suscripciones SET estado = 'cancelada' WHERE id = ?").run(sub.id);
  res.json({
    message: `Tu suscripción ha sido cancelada. Mantendrás el acceso Premium hasta el ${new Date(sub.fecha_vencimiento).toLocaleDateString('es-PE')}.`,
    user: buildUserPayload(req.user!),
  });
});

// ==================== RECIPES & SMART SEARCH ====================
app.get('/api/categories', (_req: Request, res: Response) => {
  const counts = db.prepare(`
    SELECT categoria, tipo_acceso, COUNT(*) as total
    FROM recetas
    WHERE estado_publicacion = 'publicada'
    GROUP BY categoria, tipo_acceso
  `).all() as Array<{ categoria: string; tipo_acceso: string; total: number }>;

  res.json({
    freeCategories: FREE_CATEGORIES,
    premiumCategories: PREMIUM_CATEGORIES,
    counts,
  });
});

app.get('/api/recipes', optionalAuth, (req: AuthRequest, res: Response) => {
  const isPremiumUser = req.user
    ? Boolean(getActiveSubscription(req.user.id)) || req.user.rol === 'admin'
    : false;

  const {
    categoria,
    tipo_acceso,
    q,
    ingredientes,
    maxTiempo,
    dificultad,
    destacada,
    popular,
  } = req.query;

  let sql = `SELECT * FROM recetas WHERE estado_publicacion = 'publicada'`;
  const params: unknown[] = [];

  if (categoria && categoria !== 'Todas') {
    sql += ` AND categoria = ?`;
    params.push(String(categoria));
  }
  if (tipo_acceso && (tipo_acceso === 'Gratis' || tipo_acceso === 'Premium')) {
    sql += ` AND tipo_acceso = ?`;
    params.push(String(tipo_acceso));
  }
  if (maxTiempo) {
    sql += ` AND tiempo <= ?`;
    params.push(Number(maxTiempo));
  }
  if (dificultad && dificultad !== 'Todas') {
    sql += ` AND dificultad = ?`;
    params.push(String(dificultad));
  }
  if (destacada === '1') {
    sql += ` AND destacada = 1`;
  }
  if (popular === '1') {
    sql += ` AND popular = 1`;
  }
  if (q && String(q).trim() !== '') {
    const term = `%${String(q).trim().toLowerCase()}%`;
    sql += ` AND (LOWER(nombre) LIKE ? OR LOWER(descripcion) LIKE ? OR LOWER(categoria) LIKE ?)`;
    params.push(term, term, term);
  }

  sql += ` ORDER BY destacada DESC, popular DESC, id ASC`;

  const recipes = db.prepare(sql).all(...params) as Array<{
    id: number;
    nombre: string;
    descripcion: string;
    fotografia: string | null;
    categoria: string;
    tipo_acceso: 'Gratis' | 'Premium';
    tiempo: number;
    porciones: number;
    dificultad: string;
    consejos: string;
    apto_ninos: string | null;
    destacada: number;
    popular: number;
  }>;

  const searchIngredients = ingredientes
    ? String(ingredientes)
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
    : [];

  const getIngStmt = db.prepare('SELECT nombre, cantidad, unidad FROM ingredientes WHERE receta_id = ?');

  let enriched = recipes.map((r) => {
    const locked = r.tipo_acceso === 'Premium' && !isPremiumUser;
    const ingRows = getIngStmt.all(r.id) as Array<{ nombre: string; cantidad: string; unidad: string }>;

    let matchCount = 0;
    const matchedIngredients: string[] = [];
    const missingIngredients: string[] = [];

    if (searchIngredients.length > 0) {
      for (const ing of ingRows) {
        const ingLower = ing.nombre.toLowerCase();
        const isMatch = searchIngredients.some((si) => ingLower.includes(si) || si.includes(ingLower));
        if (isMatch) {
          matchCount++;
          if (!locked) matchedIngredients.push(ing.nombre);
        } else {
          if (!locked) missingIngredients.push(ing.nombre);
        }
      }
    }

    // Server-side protection: strip exclusive fields when locked
    return {
      id: r.id,
      nombre: r.nombre,
      descripcion: r.descripcion,
      fotografia: r.fotografia,
      categoria: r.categoria,
      tipo_acceso: r.tipo_acceso,
      tiempo: r.tiempo,
      porciones: r.porciones,
      dificultad: r.dificultad,
      destacada: r.destacada,
      popular: r.popular,
      locked,
      totalIngredients: ingRows.length,
      matchCount,
      matchedIngredients: locked ? [] : matchedIngredients,
      missingIngredients: locked ? [] : missingIngredients,
    };
  });

  if (searchIngredients.length > 0) {
    enriched = enriched
      .filter((r) => r.matchCount > 0)
      .sort((a, b) => b.matchCount - a.matchCount || a.missingIngredients.length - b.missingIngredients.length);
  }

  res.json({ recipes: enriched, isPremiumUser });
});

app.get('/api/recipes/:id', optionalAuth, (req: AuthRequest, res: Response) => {
  const recipeId = Number(req.params.id);
  const recipe = db.prepare("SELECT * FROM recetas WHERE id = ? AND estado_publicacion = 'publicada'").get(recipeId) as {
    id: number;
    nombre: string;
    descripcion: string;
    fotografia: string | null;
    categoria: string;
    tipo_acceso: 'Gratis' | 'Premium';
    tiempo: number;
    porciones: number;
    dificultad: string;
    consejos: string;
    apto_ninos: string | null;
  } | undefined;

  if (!recipe) {
    return res.status(404).json({ error: 'Receta no encontrada.' });
  }

  const isPremiumUser = req.user
    ? Boolean(getActiveSubscription(req.user.id)) || req.user.rol === 'admin'
    : false;
  const locked = recipe.tipo_acceso === 'Premium' && !isPremiumUser;

  if (locked) {
    // Strictly withhold ingredients, steps, tips, and video from unauthorized/free users
    return res.json({
      recipe: {
        id: recipe.id,
        nombre: recipe.nombre,
        descripcion: recipe.descripcion,
        fotografia: recipe.fotografia,
        categoria: recipe.categoria,
        tipo_acceso: recipe.tipo_acceso,
        tiempo: recipe.tiempo,
        porciones: recipe.porciones,
        dificultad: recipe.dificultad,
        locked: true,
      },
      related: [],
    });
  }

  const ingredientes = db.prepare('SELECT id, nombre, cantidad, unidad FROM ingredientes WHERE receta_id = ?').all(recipeId);
  const preparaciones = db.prepare('SELECT id, numero_paso, instruccion FROM preparaciones WHERE receta_id = ? ORDER BY numero_paso ASC').all(recipeId);
  const video = db.prepare("SELECT archivo_multimedia FROM videos WHERE receta_id = ? AND estado_publicacion = 'publicado'").get(recipeId) as { archivo_multimedia: string } | undefined;

  const related = db.prepare(`
    SELECT id, nombre, descripcion, fotografia, categoria, tipo_acceso, tiempo, porciones, dificultad
    FROM recetas
    WHERE categoria = ? AND id != ? AND estado_publicacion = 'publicada'
    LIMIT 3
  `).all(recipe.categoria, recipeId);

  res.json({
    recipe: {
      ...recipe,
      locked: false,
      ingredientes,
      preparaciones,
      videoUrl: video ? video.archivo_multimedia : null,
    },
    related,
  });
});

// ==================== FAVORITES, PREPARED & SHOPPING LIST ====================
app.post('/api/favorites/:recipeId', requireAuth, (req: AuthRequest, res: Response) => {
  const recipeId = Number(req.params.recipeId);
  db.prepare('INSERT OR IGNORE INTO favoritos (usuaria_id, receta_id) VALUES (?, ?)').run(req.user!.id, recipeId);
  res.json({ user: buildUserPayload(req.user!) });
});

app.delete('/api/favorites/:recipeId', requireAuth, (req: AuthRequest, res: Response) => {
  const recipeId = Number(req.params.recipeId);
  db.prepare('DELETE FROM favoritos WHERE usuaria_id = ? AND receta_id = ?').run(req.user!.id, recipeId);
  res.json({ user: buildUserPayload(req.user!) });
});

app.post('/api/prepared/:recipeId', requireAuth, (req: AuthRequest, res: Response) => {
  const recipeId = Number(req.params.recipeId);
  db.prepare('INSERT OR IGNORE INTO recetas_preparadas (usuaria_id, receta_id) VALUES (?, ?)').run(req.user!.id, recipeId);
  res.json({ user: buildUserPayload(req.user!) });
});

app.delete('/api/prepared/:recipeId', requireAuth, (req: AuthRequest, res: Response) => {
  const recipeId = Number(req.params.recipeId);
  db.prepare('DELETE FROM recetas_preparadas WHERE usuaria_id = ? AND receta_id = ?').run(req.user!.id, recipeId);
  res.json({ user: buildUserPayload(req.user!) });
});

app.get('/api/shopping-list', requireAuth, (req: AuthRequest, res: Response) => {
  const items = db.prepare('SELECT * FROM lista_compras WHERE usuaria_id = ? ORDER BY comprado ASC, id DESC').all(req.user!.id);
  res.json({ items });
});

app.post('/api/shopping-list', requireAuth, (req: AuthRequest, res: Response) => {
  const { ingrediente, cantidad, categoria } = req.body;
  if (!ingrediente) {
    return res.status(400).json({ error: 'Ingresa el nombre del ingrediente.' });
  }
  db.prepare(`
    INSERT INTO lista_compras (usuaria_id, ingrediente, cantidad, categoria, comprado)
    VALUES (?, ?, ?, ?, 0)
  `).run(req.user!.id, String(ingrediente).trim(), String(cantidad || '1 unidad').trim(), String(categoria || 'Despensa'));
  const items = db.prepare('SELECT * FROM lista_compras WHERE usuaria_id = ? ORDER BY comprado ASC, id DESC').all(req.user!.id);
  res.status(201).json({ items });
});

app.post('/api/shopping-list/from-recipe/:recipeId', requireAuth, (req: AuthRequest, res: Response) => {
  const recipeId = Number(req.params.recipeId);
  const recipe = db.prepare('SELECT tipo_acceso FROM recetas WHERE id = ?').get(recipeId) as { tipo_acceso: string } | undefined;
  if (!recipe) {
    return res.status(404).json({ error: 'Receta no encontrada.' });
  }
  const isPremiumUser = Boolean(getActiveSubscription(req.user!.id)) || req.user!.rol === 'admin';
  if (recipe.tipo_acceso === 'Premium' && !isPremiumUser) {
    return res.status(403).json({ error: 'No es posible extraer ingredientes de una receta Premium bloqueada.' });
  }

  const ings = db.prepare('SELECT nombre, cantidad, unidad FROM ingredientes WHERE receta_id = ?').all(recipeId) as Array<{
    nombre: string;
    cantidad: string;
    unidad: string;
  }>;

  const insertItem = db.prepare(`
    INSERT INTO lista_compras (usuaria_id, ingrediente, cantidad, categoria, comprado)
    VALUES (?, ?, ?, 'Receta', 0)
  `);
  const tx = db.transaction(() => {
    for (const ing of ings) {
      insertItem.run(req.user!.id, ing.nombre, `${ing.cantidad} ${ing.unidad}`);
    }
  });
  tx();

  const items = db.prepare('SELECT * FROM lista_compras WHERE usuaria_id = ? ORDER BY comprado ASC, id DESC').all(req.user!.id);
  res.json({ items, addedCount: ings.length });
});

app.patch('/api/shopping-list/:id', requireAuth, (req: AuthRequest, res: Response) => {
  const id = Number(req.params.id);
  const item = db.prepare('SELECT comprado FROM lista_compras WHERE id = ? AND usuaria_id = ?').get(id, req.user!.id) as { comprado: number } | undefined;
  if (!item) {
    return res.status(404).json({ error: 'Elemento no encontrado.' });
  }
  db.prepare('UPDATE lista_compras SET comprado = ? WHERE id = ? AND usuaria_id = ?').run(item.comprado ? 0 : 1, id, req.user!.id);
  const items = db.prepare('SELECT * FROM lista_compras WHERE usuaria_id = ? ORDER BY comprado ASC, id DESC').all(req.user!.id);
  res.json({ items });
});

app.delete('/api/shopping-list/:id', requireAuth, (req: AuthRequest, res: Response) => {
  const id = Number(req.params.id);
  db.prepare('DELETE FROM lista_compras WHERE id = ? AND usuaria_id = ?').run(id, req.user!.id);
  const items = db.prepare('SELECT * FROM lista_compras WHERE usuaria_id = ? ORDER BY comprado ASC, id DESC').all(req.user!.id);
  res.json({ items });
});

// ==================== SUBSCRIPTIONS & PERU PAYMENT GATEWAY ====================
app.get('/api/subscriptions/plans', (_req: Request, res: Response) => {
  const plans = db.prepare('SELECT * FROM planes_suscripcion WHERE activo = 1 ORDER BY precio_soles ASC').all();
  const gateway = db.prepare('SELECT proveedor_activo, culqi_public_key, culqi_secret_key, mp_public_key, mp_access_token FROM configuracion_pasarela WHERE id = 1').get() as {
    proveedor_activo: 'ninguno' | 'culqi' | 'mercadopago';
    culqi_public_key: string;
    culqi_secret_key: string;
    mp_public_key: string;
    mp_access_token: string;
  };

  const isConfigured =
    (gateway.proveedor_activo === 'culqi' && Boolean(gateway.culqi_secret_key)) ||
    (gateway.proveedor_activo === 'mercadopago' && Boolean(gateway.mp_access_token));

  res.json({
    plans,
    gateway: {
      configured: isConfigured,
      provider: gateway.proveedor_activo,
      publicKey: gateway.proveedor_activo === 'culqi' ? gateway.culqi_public_key : gateway.mp_public_key,
    },
  });
});

app.post('/api/payments/create-checkout', requireAuth, async (req: AuthRequest, res: Response) => {
  const { planId } = req.body;
  const plan = db.prepare('SELECT * FROM planes_suscripcion WHERE id = ? AND activo = 1').get(Number(planId)) as {
    id: number;
    codigo: string;
    nombre: string;
    precio_soles: number;
    duracion_dias: number;
  } | undefined;

  if (!plan) {
    return res.status(404).json({ error: 'Plan de suscripción no encontrado.' });
  }

  const gateway = db.prepare('SELECT * FROM configuracion_pasarela WHERE id = 1').get() as {
    proveedor_activo: 'ninguno' | 'culqi' | 'mercadopago';
    culqi_public_key: string;
    culqi_secret_key: string;
    mp_access_token: string;
  };

  const isConfigured =
    (gateway.proveedor_activo === 'culqi' && Boolean(gateway.culqi_secret_key)) ||
    (gateway.proveedor_activo === 'mercadopago' && Boolean(gateway.mp_access_token));

  if (!isConfigured) {
    return res.status(400).json({
      configured: false,
      error: 'El servicio de pago está pendiente de configuración. Una administradora debe configurar las credenciales de Culqi o Mercado Pago Perú en el panel Administrar CreciSano.',
    });
  }

  const appUrl = process.env.APP_URL || `http://localhost:${PORT}`;

  try {
    if (gateway.proveedor_activo === 'mercadopago') {
      const mpRes = await fetch('https://api.mercadopago.com/checkout/preferences', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${gateway.mp_access_token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          items: [
            {
              title: `CreciSano - ${plan.nombre}`,
              quantity: 1,
              currency_id: 'PEN',
              unit_price: Number(plan.precio_soles),
            },
          ],
          payer: {
            email: req.user!.correo,
            name: req.user!.nombre,
          },
          external_reference: JSON.stringify({
            usuaria_id: req.user!.id,
            plan_id: plan.id,
          }),
          notification_url: `${appUrl}/api/webhooks/mercadopago`,
          back_urls: {
            success: `${appUrl}/?pago=exitoso`,
            failure: `${appUrl}/?pago=fallido`,
            pending: `${appUrl}/?pago=pendiente`,
          },
          auto_return: 'approved',
        }),
      });

      const mpData = await mpRes.json() as { init_point?: string; message?: string };
      if (!mpRes.ok || !mpData.init_point) {
        return res.status(502).json({ error: mpData.message || 'No se pudo iniciar la sesión con Mercado Pago Perú.' });
      }
      return res.json({ configured: true, provider: 'mercadopago', checkoutUrl: mpData.init_point });
    }

    if (gateway.proveedor_activo === 'culqi') {
      const orderRes = await fetch('https://api.culqi.com/v2/orders', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${gateway.culqi_secret_key}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          amount: Math.round(plan.precio_soles * 100),
          currency_code: 'PEN',
          description: `CreciSano - ${plan.nombre}`,
          order_number: `CS-${req.user!.id}-${Date.now()}`,
          client_details: {
            first_name: req.user!.nombre,
            last_name: 'CreciSano',
            email: req.user!.correo,
            phone_number: '999999999',
          },
          expiration_date: Math.floor(Date.now() / 1000) + 3600,
          metadata: {
            usuaria_id: String(req.user!.id),
            plan_id: String(plan.id),
          },
        }),
      });

      const orderData = await orderRes.json() as { id?: string; user_message?: string };
      if (!orderRes.ok || !orderData.id) {
        return res.status(502).json({ error: orderData.user_message || 'No se pudo crear la orden en Culqi Perú.' });
      }
      return res.json({
        configured: true,
        provider: 'culqi',
        orderId: orderData.id,
        publicKey: gateway.culqi_public_key,
        amountCents: Math.round(plan.precio_soles * 100),
      });
    }
  } catch {
    return res.status(502).json({ error: 'Error de comunicación con la pasarela de pagos.' });
  }
});

// Idempotent subscription activation helper called ONLY by verified webhooks
function activateSubscriptionFromWebhook(params: {
  usuariaId: number;
  planId: number;
  provider: 'culqi' | 'mercadopago';
  transactionId: string;
  amountSoles: number;
}) {
  const existingPayment = db.prepare('SELECT id FROM pagos WHERE identificador_transaccion = ?').get(params.transactionId);
  if (existingPayment) {
    return { alreadyProcessed: true };
  }

  const plan = db.prepare('SELECT * FROM planes_suscripcion WHERE id = ?').get(params.planId) as {
    nombre: string;
    duracion_dias: number;
  } | undefined;
  if (!plan) {
    throw new Error('Plan no encontrado');
  }

  const now = new Date();
  const expiration = new Date(now.getTime() + plan.duracion_dias * 24 * 60 * 60 * 1000);

  const tx = db.transaction(() => {
    db.prepare(`
      INSERT INTO pagos (usuaria_id, proveedor, identificador_transaccion, importe_soles, estado, fecha)
      VALUES (?, ?, ?, ?, 'completado', ?)
    `).run(params.usuariaId, params.provider, params.transactionId, params.amountSoles, now.toISOString());

    db.prepare(`
      INSERT INTO suscripciones (usuaria_id, plan, estado, fecha_inicio, fecha_vencimiento, identificador_transaccion)
      VALUES (?, ?, 'activa', ?, ?, ?)
    `).run(params.usuariaId, plan.nombre, now.toISOString(), expiration.toISOString(), params.transactionId);
  });

  tx();
  return { alreadyProcessed: false };
}

// Verified Webhook for Culqi
app.post('/api/webhooks/culqi', (req: Request, res: Response) => {
  const gateway = db.prepare('SELECT culqi_webhook_secret FROM configuracion_pasarela WHERE id = 1').get() as { culqi_webhook_secret: string };
  const sig = req.headers['x-culqi-signature'];
  if (gateway.culqi_webhook_secret && sig !== gateway.culqi_webhook_secret) {
    return res.status(401).json({ error: 'Firma de webhook Culqi inválida.' });
  }

  const event = req.body;
  if (event?.type === 'charge.creation.succeeded' || event?.object === 'charge') {
    const data = event.data || event;
    const txId = String(data.id);
    const meta = data.metadata || {};
    const usuariaId = Number(meta.usuaria_id);
    const planId = Number(meta.plan_id);
    const amountSoles = Number(data.amount || 0) / 100;

    if (usuariaId && planId && txId) {
      activateSubscriptionFromWebhook({
        usuariaId,
        planId,
        provider: 'culqi',
        transactionId: txId,
        amountSoles,
      });
    }
  }
  res.json({ received: true });
});

// Verified Webhook for Mercado Pago Perú
app.post('/api/webhooks/mercadopago', async (req: Request, res: Response) => {
  const gateway = db.prepare('SELECT mp_access_token, mp_webhook_secret FROM configuracion_pasarela WHERE id = 1').get() as {
    mp_access_token: string;
    mp_webhook_secret: string;
  };
  const sig = req.headers['x-signature'];
  if (gateway.mp_webhook_secret && sig !== gateway.mp_webhook_secret) {
    return res.status(401).json({ error: 'Firma de webhook Mercado Pago inválida.' });
  }

  const paymentId = req.body?.data?.id || req.query['data.id'];
  if (paymentId && gateway.mp_access_token) {
    try {
      const mpRes = await fetch(`https://api.mercadopago.com/v1/payments/${paymentId}`, {
        headers: { Authorization: `Bearer ${gateway.mp_access_token}` },
      });
      const payment = await mpRes.json() as {
        id?: number;
        status?: string;
        transaction_amount?: number;
        external_reference?: string;
      };
      if (payment.status === 'approved' && payment.external_reference) {
        const ref = JSON.parse(payment.external_reference) as { usuaria_id: number; plan_id: number };
        activateSubscriptionFromWebhook({
          usuariaId: Number(ref.usuaria_id),
          planId: Number(ref.plan_id),
          provider: 'mercadopago',
          transactionId: `MP-${payment.id}`,
          amountSoles: Number(payment.transaction_amount || 0),
        });
      }
    } catch {
      return res.status(500).json({ error: 'Error verificando pago con Mercado Pago.' });
    }
  }
  res.json({ received: true });
});

// ==================== ADMIN PANEL ROUTES ("Administrar CreciSano") ====================
app.get('/api/admin/recipes', requireAdmin, (_req: AuthRequest, res: Response) => {
  const recipes = db.prepare('SELECT * FROM recetas ORDER BY id DESC').all() as Array<Record<string, unknown>>;
  const getIng = db.prepare('SELECT id, nombre, cantidad, unidad FROM ingredientes WHERE receta_id = ?');
  const getSteps = db.prepare('SELECT id, numero_paso, instruccion FROM preparaciones WHERE receta_id = ? ORDER BY numero_paso ASC');
  const getVid = db.prepare('SELECT id, archivo_multimedia, estado_publicacion FROM videos WHERE receta_id = ?');

  const full = recipes.map((r) => ({
    ...r,
    ingredientes: getIng.all(r.id),
    preparaciones: getSteps.all(r.id),
    video: getVid.get(r.id) || null,
  }));
  res.json({ recipes: full });
});

app.post('/api/admin/recipes', requireAdmin, (req: AuthRequest, res: Response) => {
  const {
    nombre,
    descripcion,
    categoria,
    tipo_acceso,
    tiempo,
    porciones,
    dificultad,
    consejos,
    apto_ninos,
    destacada,
    popular,
    estado_publicacion,
    ingredientes,
    preparaciones,
  } = req.body;

  if (!nombre || !descripcion || !categoria) {
    return res.status(400).json({ error: 'Nombre, descripción y categoría son obligatorios.' });
  }

  const insertRec = db.prepare(`
    INSERT INTO recetas (nombre, descripcion, categoria, tipo_acceso, tiempo, porciones, dificultad, consejos, apto_ninos, destacada, popular, estado_publicacion)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const insertIng = db.prepare('INSERT INTO ingredientes (receta_id, nombre, cantidad, unidad) VALUES (?, ?, ?, ?)');
  const insertStep = db.prepare('INSERT INTO preparaciones (receta_id, numero_paso, instruccion) VALUES (?, ?, ?)');

  let newId: number | bigint = 0;
  const tx = db.transaction(() => {
    const info = insertRec.run(
      String(nombre).trim(),
      String(descripcion).trim(),
      String(categoria),
      tipo_acceso === 'Premium' ? 'Premium' : 'Gratis',
      Number(tiempo) || 20,
      Number(porciones) || 4,
      dificultad || 'Fácil',
      String(consejos || ''),
      apto_ninos ? String(apto_ninos) : null,
      destacada ? 1 : 0,
      popular ? 1 : 0,
      estado_publicacion === 'borrador' ? 'borrador' : 'publicada'
    );
    newId = info.lastInsertRowid;

    if (Array.isArray(ingredientes)) {
      for (const ing of ingredientes) {
        if (ing.nombre) {
          insertIng.run(newId, String(ing.nombre).trim(), String(ing.cantidad || '1'), String(ing.unidad || 'unidad'));
        }
      }
    }
    if (Array.isArray(preparaciones)) {
      preparaciones.forEach((step: { instruccion?: string } | string, idx: number) => {
        const text = typeof step === 'string' ? step : step.instruccion;
        if (text && text.trim()) {
          insertStep.run(newId, idx + 1, text.trim());
        }
      });
    }
  });

  tx();
  res.status(201).json({ id: newId, message: 'Receta creada correctamente.' });
});

app.put('/api/admin/recipes/:id', requireAdmin, (req: AuthRequest, res: Response) => {
  const recipeId = Number(req.params.id);
  const existing = db.prepare('SELECT id FROM recetas WHERE id = ?').get(recipeId);
  if (!existing) {
    return res.status(404).json({ error: 'Receta no encontrada.' });
  }

  const {
    nombre,
    descripcion,
    categoria,
    tipo_acceso,
    tiempo,
    porciones,
    dificultad,
    consejos,
    apto_ninos,
    destacada,
    popular,
    estado_publicacion,
    ingredientes,
    preparaciones,
  } = req.body;

  const tx = db.transaction(() => {
    db.prepare(`
      UPDATE recetas
      SET nombre = ?, descripcion = ?, categoria = ?, tipo_acceso = ?, tiempo = ?, porciones = ?,
          dificultad = ?, consejos = ?, apto_ninos = ?, destacada = ?, popular = ?, estado_publicacion = ?
      WHERE id = ?
    `).run(
      String(nombre).trim(),
      String(descripcion).trim(),
      String(categoria),
      tipo_acceso === 'Premium' ? 'Premium' : 'Gratis',
      Number(tiempo) || 20,
      Number(porciones) || 4,
      dificultad || 'Fácil',
      String(consejos || ''),
      apto_ninos ? String(apto_ninos) : null,
      destacada ? 1 : 0,
      popular ? 1 : 0,
      estado_publicacion === 'borrador' ? 'borrador' : 'publicada',
      recipeId
    );

    if (Array.isArray(ingredientes)) {
      db.prepare('DELETE FROM ingredientes WHERE receta_id = ?').run(recipeId);
      const insertIng = db.prepare('INSERT INTO ingredientes (receta_id, nombre, cantidad, unidad) VALUES (?, ?, ?, ?)');
      for (const ing of ingredientes) {
        if (ing.nombre) {
          insertIng.run(recipeId, String(ing.nombre).trim(), String(ing.cantidad || '1'), String(ing.unidad || 'unidad'));
        }
      }
    }

    if (Array.isArray(preparaciones)) {
      db.prepare('DELETE FROM preparaciones WHERE receta_id = ?').run(recipeId);
      const insertStep = db.prepare('INSERT INTO preparaciones (receta_id, numero_paso, instruccion) VALUES (?, ?, ?)');
      preparaciones.forEach((step: { instruccion?: string } | string, idx: number) => {
        const text = typeof step === 'string' ? step : step.instruccion;
        if (text && text.trim()) {
          insertStep.run(recipeId, idx + 1, text.trim());
        }
      });
    }
  });

  tx();
  res.json({ message: 'Receta actualizada correctamente.' });
});

app.delete('/api/admin/recipes/:id', requireAdmin, (req: AuthRequest, res: Response) => {
  const recipeId = Number(req.params.id);
  db.prepare('DELETE FROM recetas WHERE id = ?').run(recipeId);
  res.json({ message: 'Receta eliminada.' });
});

app.post('/api/admin/recipes/:id/photo', requireAdmin, uploadImage.single('photo'), (req: AuthRequest, res: Response) => {
  const recipeId = Number(req.params.id);
  if (!req.file) {
    return res.status(400).json({ error: 'Selecciona una imagen válida (JPG, JPEG, PNG o WEBP).' });
  }
  const photoUrl = `/uploads/images/${req.file.filename}`;
  db.prepare('UPDATE recetas SET fotografia = ? WHERE id = ?').run(photoUrl, recipeId);
  res.json({ fotografia: photoUrl, message: 'Fotografía actualizada.' });
});

app.post('/api/admin/recipes/:id/video', requireAdmin, uploadVideo.single('video'), (req: AuthRequest, res: Response) => {
  const recipeId = Number(req.params.id);
  if (!req.file) {
    return res.status(400).json({ error: 'Selecciona un archivo de video válido (MP4, WEBM o MOV).' });
  }
  const videoUrl = `/uploads/videos/${req.file.filename}`;
  db.prepare(`
    INSERT INTO videos (receta_id, archivo_multimedia, estado_publicacion)
    VALUES (?, ?, 'publicado')
    ON CONFLICT(receta_id) DO UPDATE SET archivo_multimedia = excluded.archivo_multimedia, estado_publicacion = 'publicado'
  `).run(recipeId, videoUrl);
  res.json({ videoUrl, message: 'Video original subido y asociado a la receta.' });
});

app.patch('/api/admin/recipes/:id/video', requireAdmin, (req: AuthRequest, res: Response) => {
  const recipeId = Number(req.params.id);
  const { estado_publicacion } = req.body;
  db.prepare('UPDATE videos SET estado_publicacion = ? WHERE receta_id = ?').run(
    estado_publicacion === 'oculto' ? 'oculto' : 'publicado',
    recipeId
  );
  res.json({ message: 'Estado del video actualizado.' });
});

app.delete('/api/admin/recipes/:id/video', requireAdmin, (req: AuthRequest, res: Response) => {
  const recipeId = Number(req.params.id);
  db.prepare('DELETE FROM videos WHERE receta_id = ?').run(recipeId);
  res.json({ message: 'Video eliminado de la receta.' });
});

app.get('/api/admin/users', requireAdmin, (_req: AuthRequest, res: Response) => {
  const users = db.prepare('SELECT id, nombre, correo, rol, foto_perfil, fecha_registro FROM usuarios ORDER BY id ASC').all() as Array<AuthUser & { fecha_registro: string }>;
  const enriched = users.map((u) => {
    const sub = getActiveSubscription(u.id);
    const payments = db.prepare('SELECT * FROM pagos WHERE usuaria_id = ? ORDER BY datetime(fecha) DESC').all(u.id);
    return {
      ...u,
      membresia: sub ? 'Premium' : 'Gratuita',
      suscripcion: sub,
      pagos: payments,
    };
  });
  res.json({ users: enriched });
});

app.patch('/api/admin/users/:id/role', requireAdmin, (req: AuthRequest, res: Response) => {
  const targetId = Number(req.params.id);
  const { rol } = req.body;
  if (targetId === req.user!.id) {
    return res.status(400).json({ error: 'No puedes cambiar tu propio rol de administradora.' });
  }
  db.prepare('UPDATE usuarios SET rol = ? WHERE id = ?').run(rol === 'admin' ? 'admin' : 'usuaria', targetId);
  res.json({ message: 'Permisos actualizados.' });
});

app.put('/api/admin/plans/:id', requireAdmin, (req: AuthRequest, res: Response) => {
  const planId = Number(req.params.id);
  const { nombre, precio_soles, duracion_dias, condiciones_renovacion } = req.body;
  db.prepare(`
    UPDATE planes_suscripcion
    SET nombre = ?, precio_soles = ?, duracion_dias = ?, condiciones_renovacion = ?
    WHERE id = ?
  `).run(
    String(nombre).trim(),
    Number(precio_soles),
    Number(duracion_dias),
    String(condiciones_renovacion).trim(),
    planId
  );
  res.json({ message: 'Plan actualizado en soles peruanos (S/).' });
});

app.get('/api/admin/gateway', requireAdmin, (_req: AuthRequest, res: Response) => {
  const gateway = db.prepare('SELECT * FROM configuracion_pasarela WHERE id = 1').get();
  res.json({ gateway });
});

app.put('/api/admin/gateway', requireAdmin, (req: AuthRequest, res: Response) => {
  const {
    proveedor_activo,
    culqi_public_key,
    culqi_secret_key,
    culqi_webhook_secret,
    mp_public_key,
    mp_access_token,
    mp_webhook_secret,
  } = req.body;

  db.prepare(`
    UPDATE configuracion_pasarela
    SET proveedor_activo = ?,
        culqi_public_key = ?,
        culqi_secret_key = ?,
        culqi_webhook_secret = ?,
        mp_public_key = ?,
        mp_access_token = ?,
        mp_webhook_secret = ?
    WHERE id = 1
  `).run(
    proveedor_activo || 'ninguno',
    culqi_public_key || '',
    culqi_secret_key || '',
    culqi_webhook_secret || '',
    mp_public_key || '',
    mp_access_token || '',
    mp_webhook_secret || ''
  );

  res.json({ message: 'Configuración de pasarela de pago guardada.' });
});

// ==================== VITE / PRODUCTION STATIC SERVER ====================
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`CreciSano server running on http://localhost:${PORT}`);
  });
}

startServer();
