const path = require("path");

// Charger les variables d'environnement depuis le fichier .env
require("dotenv").config({ path: path.join(__dirname, ".env") });

const express = require("express");
const multer = require("multer");
const fs = require("fs");
const fsp = require("fs").promises;
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
// const authenticateToken = require('./authMiddleware')

const app = express();
app.use(cors());
app.use(express.json());

const USERS_FILE = path.join(__dirname, "data", "userData.json");
const MODELS_FILE = path.join(__dirname, "data", "model.json");
const TEMPLATES_FILE = path.join(__dirname, "data", "templates.json");
const CATEGORIES_FILE = path.join(__dirname, "data", "categories.json");
const SHOPS_FILE = path.join(__dirname, "data", "shops.json");
const IMAGES_TEMPLATE_FILE = path.join(
  __dirname,
  "data",
  "imagesTemplate.json"
);
const CANVAS_FILE = path.join(__dirname, "data", "canvas.json");

// Dossier principal pour les uploads
const UPLOAD_BASE_DIR = path.join(__dirname, "uploads");
fs.mkdirSync(UPLOAD_BASE_DIR, { recursive: true }); // S'assurer que le dossier uploads existe

const JWT_SECRET =
  process.env.JWT_SECRET || "K8v$3nPz!xR7@qL2#fW9^mT1&uY6*eB0ZsJhC4gX";

const PORT = process.env.PORT || 8080;

// Log pour vérifier que les variables d'environnement sont bien lues
console.log("🔧 Variables d'environnement:");
console.log("   PORT:", process.env.PORT);
console.log("   PORT utilisé:", PORT);
console.log("   JWT_SECRET:", process.env.JWT_SECRET ? "Défini" : "Non défini");
console.log("   BASE_URL:", process.env.BASE_URL);

// Fonction utilitaire pour remplacer les variables d'environnement dans les chaînes
function replaceEnvVars(str) {
  if (typeof str !== "string") return str;
  return str.replace(/\$\{([^}]+)\}/g, (match, varName) => {
    return process.env[varName] || match;
  });
}

// Fonction pour traiter récursivement un objet et remplacer les variables d'environnement
function processEnvVars(obj) {
  if (typeof obj === "string") {
    return replaceEnvVars(obj);
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => processEnvVars(item));
  }
  if (obj && typeof obj === "object") {
    const processed = {};
    for (const [key, value] of Object.entries(obj)) {
      processed[key] = processEnvVars(value);
    }
    return processed;
  }
  return obj;
}

/////////////////////////////////////
//Users
/////////////////////////////////////

//Check role
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).json({ error: "Accès interdit" });
    }
    next();
  };
}

function authenticateToken(req, res, next) {
  console.log("🔐 Middleware d'authentification appelé");
  console.log("📋 Headers:", req.headers);
  
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    console.log("❌ Aucun token fourni");
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.log("❌ Token invalide:", err.message);
      return res.sendStatus(403);
    }

    const users = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
    const user = users.find((u) => u.id === decoded.id);
    if (!user) {
      console.log("❌ Utilisateur non trouvé");
      return res.sendStatus(404);
    }

    console.log("✅ Authentification réussie pour l'utilisateur:", user.email);
    req.user = user;
    next();
  });
}

/**
 * Connexion utilisateur
 */
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const users = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  const user = users.find((u) => u.email === email);

  if (!user) {
    return res
      .status(401)
      .json({ message: "Email ou mot de passe incorrect." });
  }

  bcrypt.compare(
    password,
    user.passwordHash || user.password,
    (err, isValid) => {
      if (err) {
        console.error("Error comparing passwords:", err);
        return res
          .status(500)
          .json({ message: "Erreur serveur lors de la connexion." });
      }
      if (!isValid) {
        return res
          .status(401)
          .json({ message: "Email ou mot de passe incorrect." });
      }

      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        JWT_SECRET,
        {
          expiresIn: "2h",
        }
      );
      res.json({ token });
    }
  );
});

app.get("/api/users", (req, res) => {
  const filePath = path.join(__dirname, "data", "userData.json");
  try {
    const fileData = fs.readFileSync(filePath, "utf-8");
    const users = JSON.parse(fileData);

    // Remove passwordHash from each user object before sending the response
    const usersWithoutPasswordHash = users.map((user) => {
      const { passwordHash, password, ...userWithoutSensitiveData } = user; // Also remove plain password if present for older entries
      return userWithoutSensitiveData;
    });

    // Traiter les variables d'environnement dans les données
    const processedData = processEnvVars(usersWithoutPasswordHash);
    res.json(processedData);
  } catch (error) {
    console.error("Erreur lors de la lecture de userData.json :", error);
    res.status(500).json({ error: "Impossible de lire userData.json" });
  }
});

// Route pour mettre à jour un utilisateur (modification partielle)
app.patch("/api/users/:id", authenticateToken, async (req, res) => {
  const userIdToUpdate = parseInt(req.params.id, 10);
  const authenticatedUser = req.user;
  const updates = req.body;

  // Vérification des autorisations
  if (
    authenticatedUser.id !== userIdToUpdate &&
    authenticatedUser.role !== "super_admin"
  ) {
    return res
      .status(403)
      .json({ message: "Accès non autorisé pour modifier cet utilisateur." });
  }

  let users = [];
  try {
    const usersData = fs.readFileSync(USERS_FILE, "utf8");
    users = JSON.parse(usersData);
  } catch (readError) {
    if (readError.code === "ENOENT") {
      console.error("userData.json non trouvé:", readError);
      return res
        .status(500)
        .json({ message: "Fichier de données utilisateur non trouvé." });
    }
    console.error("Erreur lecture ou parse userData.json:", readError);
    return res.status(500).json({
      message: "Erreur serveur lors de la lecture des données utilisateurs.",
    });
  }

  const userIndex = users.findIndex((u) => u.id === userIdToUpdate);

  if (userIndex === -1) {
    return res.status(404).json({ message: "Utilisateur non trouvé." });
  }

  // On travaille sur une copie pour ne pas modifier l'original en cas d'erreur en cours de route
  const userToUpdate = { ...users[userIndex] };

  // Interdire la modification de l'ID
  if (updates.hasOwnProperty("id")) {
    delete updates.id;
  }

  // Gestion de la mise à jour de l'email (avec vérification d'unicité)
  if (
    updates.hasOwnProperty("email") &&
    typeof updates.email === "string" &&
    updates.email !== userToUpdate.email
  ) {
    const emailExists = users.some(
      (u) => u.email === updates.email && u.id !== userIdToUpdate
    );
    if (emailExists) {
      return res
        .status(409)
        .json({ message: "Cet email est déjà utilisé par un autre compte." });
    }
    userToUpdate.email = updates.email;
  }

  // Gestion de la mise à jour du mot de passe
  if (updates.hasOwnProperty("password")) {
    if (typeof updates.password !== "string" || updates.password.length < 6) {
      return res.status(400).json({
        message:
          "Le mot de passe doit être une chaîne d'au moins 6 caractères.",
      });
    }
    try {
      userToUpdate.passwordHash = await bcrypt.hash(updates.password, 10);
      delete userToUpdate.password; // Supprimer l'ancien champ mot de passe en clair s'il existe
    } catch (hashError) {
      console.error(
        "Erreur hachage mot de passe lors de la mise à jour:",
        hashError
      );
      return res.status(500).json({
        message: "Erreur serveur lors de la mise à jour du mot de passe.",
      });
    }
  }

  // Appliquer les autres mises à jour autorisées (name, company, role)
  const allowedDirectUpdateFields = ["name", "company", "role"];
  for (const field of allowedDirectUpdateFields) {
    if (updates.hasOwnProperty(field)) {
      userToUpdate[field] = updates[field];
    }
  }

  // Mettre à jour l'utilisateur dans le tableau
  users[userIndex] = userToUpdate;

  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    const { passwordHash, password, ...updatedUserWithoutSensitiveData } =
      userToUpdate;
    res.json({
      message: "Utilisateur mis à jour avec succès.",
      user: updatedUserWithoutSensitiveData,
    });
  } catch (writeError) {
    console.error(
      "Erreur écriture userData.json lors de la mise à jour:",
      writeError
    );
    return res.status(500).json({
      message: "Erreur serveur lors de la sauvegarde des modifications.",
    });
  }
});

/**
 * Route protégée : récupérer les infos utilisateur connecté
 */
app.get("/api/get-me", authenticateToken, (req, res) => {
  const users = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  const user = users.find((u) => u.id === req.user.id);

  if (!user) return res.status(404).json({ error: "Utilisateur non trouvé" });

  const { passwordHash, ...userWithoutPassword } = user;
  res.json(userWithoutPassword);
});

/**
 * Enregistrement d'un nouvel utilisateur
 */
app.post("/api/register", async (req, res) => {
  const { email, password, name, company, role } = req.body;

  if (!email || !password || !name) {
    return res
      .status(400)
      .json({ error: "Champs requis : email, mot de passe, nom." });
  }

  let users = [];
  try {
    const usersData = fs.readFileSync(USERS_FILE, "utf8");
    users = JSON.parse(usersData);
  } catch (readError) {
    console.warn(
      "Could not read or parse userData.json, starting with empty users array.",
      readError
    );
  }

  const emailExists = users.some((u) => u.email === email);
  if (emailExists) {
    return res.status(409).json({ error: "Email déjà utilisé" });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = {
      id: users.length ? Math.max(...users.map((u) => u.id)) + 1 : 1,
      email,
      passwordHash,
      name,
      company: company || null,
      role: role || "user",
    };

    users.push(newUser);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

    const { passwordHash: _, ...userWithoutPasswordHash } = newUser;
    res.status(201).json({
      message: "Utilisateur créé avec succès",
      user: userWithoutPasswordHash,
    });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Erreur lors de la création de l'utilisateur" });
  }
});

// Route pour supprimer un utilisateur
app.delete("/api/users/:id", authenticateToken, async (req, res) => {
  const userIdToDelete = parseInt(req.params.id, 10);
  const authenticatedUser = req.user;

  // Vérification des autorisations
  // Seul un super_admin peut supprimer un utilisateur, et il ne peut pas se supprimer lui-même via cette route.
  if (authenticatedUser.role !== "super_admin") {
    return res
      .status(403)
      .json({ message: "Accès non autorisé pour supprimer un utilisateur." });
  }
  if (authenticatedUser.id === userIdToDelete) {
    return res.status(400).json({
      message:
        "Un administrateur ne peut pas se supprimer lui-même via cette route.",
    });
  }

  let users = [];
  try {
    const usersData = fs.readFileSync(USERS_FILE, "utf8");
    users = JSON.parse(usersData);
  } catch (readError) {
    if (readError.code === "ENOENT") {
      console.error(
        "userData.json non trouvé lors de la tentative de suppression:",
        readError
      );
      return res
        .status(500)
        .json({ message: "Fichier de données utilisateur non trouvé." });
    }
    console.error(
      "Erreur lecture ou parse userData.json lors de la suppression:",
      readError
    );
    return res.status(500).json({
      message: "Erreur serveur lors de la lecture des données utilisateurs.",
    });
  }

  const userIndexToDelete = users.findIndex((u) => u.id === userIdToDelete);

  if (userIndexToDelete === -1) {
    return res.status(404).json({ message: "Utilisateur non trouvé." });
  }

  // Supprimer l'utilisateur du tableau
  users.splice(userIndexToDelete, 1);

  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    res.json({ message: "Utilisateur supprimé avec succès." });
  } catch (writeError) {
    console.error(
      "Erreur écriture userData.json lors de la suppression:",
      writeError
    );
    // Il serait bon de remettre l'utilisateur si l'écriture échoue, mais c'est plus complexe.
    // Pour l'instant, on signale l'erreur.
    return res.status(500).json({
      message:
        "Erreur serveur lors de la sauvegarde des modifications après suppression.",
    });
  }
});

/////////////////////////////////////
//models
/////////////////////////////////////
// Multer : config fusionnée pour miniature dans add-model
const storageAddModel = multer.diskStorage({
  destination: function (req, file, cb) {
    // Le categoryId n'est pas encore connu ici, donc on utilise temporairement './uploads/tmp'
    const tempDir = path.join(__dirname, "uploads", "tmp");
    fs.mkdirSync(tempDir, { recursive: true });
    cb(null, tempDir);
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});

const uploadAddModel = multer({ storage: storageAddModel });

// Configuration multer pour la modification des miniatures
const storageUpdateThumbnail = multer.diskStorage({
  destination: function (req, file, cb) {
    // Le categoryId n'est pas encore connu ici, donc on utilise temporairement './uploads/tmp'
    const tempDir = path.join(__dirname, "uploads", "tmp");
    fs.mkdirSync(tempDir, { recursive: true });
    cb(null, tempDir);
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});

const uploadUpdateThumbnail = multer({ storage: storageUpdateThumbnail });

// Route combinée pour ajout modèle + upload miniature +  ajout template
app.post("/api/add-model", uploadAddModel.single("image"), (req, res) => {
  const dataPath = path.join(__dirname, "data", "model.json");
  const templatePath = path.join(__dirname, "data", "templates.json");
  const imageTemplatePath = path.join(__dirname, "data", "imagesTemplate.json");

  const newData = JSON.parse(req.body.data); // Le JSON est envoyé dans un champ 'data'

  fs.readFile(dataPath, "utf8", (err, data) => {
    if (err)
      return res.status(500).json({ error: "Erreur lecture model.json" });

    fs.readFile(templatePath, "utf8", (err, templateData) => {
      if (err)
        return res.status(500).json({ error: "Erreur lecture templates.json" });

      fs.readFile(imageTemplatePath, "utf8", (err, imagesTemplateData) => {
        if (err)
          return res
            .status(500)
            .json({ error: "Erreur lecture templates.json" });

        let modeldata = [];
        let templatesData = [];
        let imageTemplateData = [];
        try {
          modeldata = JSON.parse(data);
          templatesData = JSON.parse(templateData);
          imageTemplateData = JSON.parse(imagesTemplateData);
        } catch (e) {
          return res.status(500).json({ error: "Fichier JSON invalide" });
        }

        const lastId = modeldata.reduce(
          (maxId, item) => (item.id > maxId ? item.id : maxId),
          0
        );
        const lastTemplateId = templatesData.reduce(
          (maxId, item) => (item.id > maxId ? item.id : maxId),
          0
        );

        const imageExists = imageTemplateData.some(
          (img) => img.name === newData.image
        );

        const templateExist = imageTemplateData.find(
          (img) => img.name === newData.image
        );

        const nextId = lastId + 1;
        const nextTemplateId = !imageExists
          ? lastTemplateId + 1
          : templateExist.templateId;
        const newEntry = {
          id: nextId,
          templateId: nextTemplateId,
          categoryId: newData.categoryId,
          dimensionId: newData.dimensionId,
          canvas: newData.canvas,
        };

        // Ajout dans le JSON
        modeldata.push(newEntry);

        if (!imageExists) {
          const lastImageId = imageTemplateData.reduce(
            (maxId, item) => (item.id > maxId ? item.id : maxId),
            0
          );
          const nextImageId = lastImageId + 1;

          const newImageData = {
            id: nextImageId,
            name: newData.image,
            templateId: nextTemplateId,
          };
          console.log("imageTemplate ajouté");
          // Ajout dans le JSON
          imageTemplateData.push(newImageData);

          fs.writeFile(
            imageTemplatePath,
            JSON.stringify(imageTemplateData, null, 2),
            (err) => {
              if (err) {
                console.error("Erreur écriture imagesTemplate.json", err);
              }
            }
          );
        }
        fs.writeFile(dataPath, JSON.stringify(modeldata, null, 2), (err) => {
          if (err)
            return res
              .status(500)
              .json({ error: "Erreur écriture model.json" });

          // Gérer l'image miniature si elle est présente
          if (req.file && newData.image && !imageExists) {
            const destDir = path.join(
              __dirname,
              "uploads",
              "miniatures",
              String(newData.categoryId)
            );
            fs.mkdirSync(destDir, { recursive: true });

            const destPath = path.join(destDir, newData.image);
            fs.rename(req.file.path, destPath, (err) => {
              if (err)
                return res
                  .status(500)
                  .json({ error: "Erreur déplacement miniature" });

              res.status(200).json({
                message: "Modèle ajouté avec miniature",
                model: newEntry,
                miniature: `/uploads/miniatures/${nextId}/${newData.image}`,
              });
            });
          } else {
            res.status(200).json({
              message: "Modèle ajouté (sans miniature)",
              model: newEntry,
            });
          }
        });
      });
    });
  });
});

app.get("/api/models", (req, res) => {
  const filePath = path.join(__dirname, "data", "model.json");
  try {
    const data = fs.readFileSync(filePath, "utf-8");
    const modelData = JSON.parse(data);
    // Traiter les variables d'environnement dans les données
    const processedData = processEnvVars(modelData);
    res.json(processedData);
  } catch (error) {
    console.error("Erreur lors de la lecture de model.json :", error);
    res.status(500).json({ error: "Impossible de lire model.json" });
  }
});

app.put("/api/update-models/:id", authenticateToken, (req, res) => {
  const modelId = parseInt(req.params.id);
  const updatedModel = req.body;

  const filePath = path.join(__dirname, "data", "model.json");

  try {
    const data = fs.readFileSync(filePath, "utf-8");
    const models = JSON.parse(data);

    const index = models.findIndex((model) => model.id === modelId);
    if (index === -1) {
      return res.status(404).json({ error: "Modèle non trouvé" });
    }

    // Met à jour les champs du modèle
    models[index] = { ...models[index], ...updatedModel, id: modelId };

    fs.writeFileSync(filePath, JSON.stringify(models, null, 2), "utf-8");

    res.json(models[index]);
  } catch (error) {
    console.error("Erreur lors de la mise à jour du modèle :", error);
    res.status(500).json({ error: "Impossible de mettre à jour le modèle" });
  }
});

app.patch("/api/patch-models/:id", (req, res) => {
  const modelId = parseInt(req.params.id);
  const patchData = JSON.parse(req.body.data);

  const filePath = path.join(__dirname, "data", "model.json");

  try {
    const data = fs.readFileSync(filePath, "utf-8");
    const models = JSON.parse(data);

    const index = models.findIndex((model) => model.id === modelId);
    if (index === -1) {
      return res.status(404).json({ error: "Modèle non trouvé" });
    }

    // Appliquer seulement les champs modifiés
    models[index] = { ...models[index], ...patchData, id: modelId };

    fs.writeFileSync(filePath, JSON.stringify(models, null, 2), "utf-8");

    res.json(models[index]);
  } catch (error) {
    console.error("Erreur lors du patch du modèle :", error);
    res.status(500).json({ error: "Impossible de patcher le modèle" });
  }
});

// Route pour modifier la miniature d'un template
app.patch("/api/template/:id/thumbnail/:name", uploadUpdateThumbnail.single("image"), async (req, res) => {
  const categoryId = parseInt(req.params.id);
  const imageName = req.params.name; // Traité comme une chaîne, pas converti en entier
  
  if (!req.file) {
    return res.status(400).json({ error: "Aucune image fournie" });
  }

  try {
    // Lire les données du template
    const templatesData = await fsp.readFile(TEMPLATES_FILE, "utf8");
    const templates = JSON.parse(templatesData);
    
    const templateIndex = templates.findIndex((template) => template.categoryId === categoryId && template.image === imageName);
    if (templateIndex === -1) {
      return res.status(404).json({ error: "Template non trouvé" });
    }
    
    const template = templates[templateIndex];
    
    // Lire les données des images template
    const imagesTemplateData = await fsp.readFile(IMAGES_TEMPLATE_FILE, "utf8");
    const imagesTemplates = JSON.parse(imagesTemplateData);
    
    // Trouver l'ancienne image template associée
    const oldImageTemplate = imagesTemplates.find(
      (img) => img.templateId === template.id && img.name === template.image
    );
    
    // Créer le dossier de destination pour la nouvelle miniature
    const destDir = path.join(
      __dirname,
      "uploads",
      "miniatures",
      String(template.categoryId)
    );
    fs.mkdirSync(destDir, { recursive: true });
    
    // Chemin de l'ancienne image (pour l'écraser)
    const oldImagePath = path.join(destDir, template.image);
    
    // Déplacer la nouvelle image (écrase l'ancienne si elle existe)
    const destPath = path.join(destDir, req.file.originalname);
    await fsp.rename(req.file.path, destPath);
    
    // Mettre à jour le nom de l'image dans le template
    const oldImageName = template.image;
    templates[templateIndex].image = req.file.originalname;
    
    // Mettre à jour le fichier templates.json
    await fsp.writeFile(TEMPLATES_FILE, JSON.stringify(templates, null, 2));
    
    // Mettre à jour ou créer l'entrée dans imagesTemplate.json
    if (oldImageTemplate) {
      // Mettre à jour l'entrée existante
      oldImageTemplate.name = req.file.originalname;
    } else {
      // Créer une nouvelle entrée
      const lastImageId = imagesTemplates.reduce(
        (maxId, item) => Math.max(maxId, item.id),
        0
      );
      const newImageData = {
        id: lastImageId + 1,
        name: req.file.originalname,
        templateId: template.id,
      };
      imagesTemplates.push(newImageData);
    }
    
    // Sauvegarder imagesTemplate.json
    await fsp.writeFile(IMAGES_TEMPLATE_FILE, JSON.stringify(imagesTemplates, null, 2));
    
    res.json({
      message: "Miniature modifiée avec succès",
      template: templates[templateIndex],
      thumbnail: `/uploads/miniatures/${template.categoryId}/${req.file.originalname}`,
      oldImage: oldImageName
    });
    
  } catch (error) {
    console.error("Erreur lors de la modification de la miniature :", error);
    
    // Nettoyer le fichier temporaire en cas d'erreur
    if (req.file) {
      try {
        await fsp.unlink(req.file.path);
      } catch (cleanupError) {
        console.warn("Erreur lors du nettoyage du fichier temporaire:", cleanupError);
      }
    }
    
    res.status(500).json({ error: "Impossible de modifier la miniature" });
  }
});

// Route pour supprimer un modèle
app.delete("/api/models/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Accès non autorisé." });
  }
  const modelIdToDelete = parseInt(req.params.id, 10);

  try {
    let models;
    try {
      const modelsData = await fsp.readFile(MODELS_FILE, "utf8");
      models = JSON.parse(modelsData);
    } catch (e) {
      if (e.code === "ENOENT")
        return res
          .status(404)
          .json({ message: "Fichier des modèles non trouvé." });
      throw e;
    }

    const modelIndex = models.findIndex((m) => m.id === modelIdToDelete);
    if (modelIndex === -1)
      return res.status(404).json({ message: "Modèle non trouvé." });

    const modelToDelete = models[modelIndex];

    // Supprimer l'image miniature associée s'il y en a une
    if (modelToDelete.image && modelToDelete.categoryId) {
      const imagePath = path.join(
        __dirname,
        "uploads",
        "miniatures",
        String(modelToDelete.categoryId),
        modelToDelete.image
      );
      try {
        await fsp.unlink(imagePath);
        console.log(`Miniature supprimée: ${imagePath}`);
      } catch (unlinkError) {
        if (unlinkError.code !== "ENOENT") {
          console.warn(
            `Erreur lors de la suppression de la miniature ${imagePath}:`,
            unlinkError
          );
          // Ne pas bloquer la suppression du modèle si la miniature ne peut être supprimée pour une autre raison que ENOENT
        }
      }
    }

    // Supprimer l'entrée associée dans imagesTemplate.json
    if (modelToDelete.templateId && modelToDelete.image) {
      try {
        let imagesTemplates;
        const imagesTemplatesData = await fsp.readFile(
          IMAGES_TEMPLATE_FILE,
          "utf8"
        );
        imagesTemplates = JSON.parse(imagesTemplatesData);
        const updatedImagesTemplates = imagesTemplates.filter(
          (it) =>
            !(
              it.templateId === modelToDelete.templateId &&
              it.name === modelToDelete.image
            )
        );
        if (updatedImagesTemplates.length < imagesTemplates.length) {
          await fsp.writeFile(
            IMAGES_TEMPLATE_FILE,
            JSON.stringify(updatedImagesTemplates, null, 2)
          );
          console.log("Entrée imageTemplate associée supprimée.");
        }
      } catch (itError) {
        if (itError.code !== "ENOENT") {
          console.warn(
            "Erreur lors de la mise à jour de imagesTemplate.json pour le modèle supprimé:",
            itError
          );
        }
      }
    }

    models.splice(modelIndex, 1);
    await fsp.writeFile(MODELS_FILE, JSON.stringify(models, null, 2));

    res.json({ message: "Modèle supprimé avec succès." });
  } catch (error) {
    console.error(
      `Erreur lors de la suppression du modèle ${modelIdToDelete}:`,
      error
    );
    res
      .status(500)
      .json({ message: "Erreur serveur lors de la suppression du modèle." });
  }
});

/////////////////////////////////////
//templates
/////////////////////////////////////
app.get("/api/templates", (req, res) => {
  const filePath = path.join(__dirname, "data", "templates.json");
  try {
    const data = fs.readFileSync(filePath, "utf-8");
    const templatesData = JSON.parse(data);
    // Traiter les variables d'environnement dans les données
    const processedData = processEnvVars(templatesData);
    res.json(processedData);
  } catch (error) {
    console.error("Erreur lors de la lecture de templates.json :", error);
    res.status(500).json({ error: "Impossible de lire templates.json" });
  }
});

app.post("/api/add-template", (req, res) => {
  const dataPath = path.join(__dirname, "data", "templates.json");

  const newData = req.body;

  if (!newData || typeof newData !== "object") {
    return res.status(400).json({ error: "Données invalides" });
  }

  // Lire le fichier actuel
  fs.readFile(dataPath, "utf8", (err, data) => {
    if (err) return res.status(500).json({ error: "Erreur lecture fichier" });

    let templatedata = [];
    try {
      templatedata = JSON.parse(data);
    } catch (e) {
      return res.status(500).json({ error: "Fichier JSON invalide" });
    }

    // Trouver le plus grand ID existant
    const lastId = templatedata.reduce((maxId, item) => {
      return item.id > maxId ? item.id : maxId;
    }, 0);

    // Assigner un nouvel ID
    const nextId = lastId + 1;
    const newEntry = { id: nextId, ...newData };

    // Ajouter la nouvelle donnée
    templatedata.push(newEntry);

    // Réécrire le fichier
    fs.writeFile(dataPath, JSON.stringify(templatedata, null, 2), (err) => {
      if (err)
        return res.status(500).json({ error: "Erreur écriture fichier" });
      res.json({ message: "Fichier mis à jour", newData });
    });
  });
});

// Route pour supprimer un template
app.delete("/api/templates/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Accès non autorisé." });
  }
  const templateIdToDelete = parseInt(req.params.id, 10);

  try {
    // Vérifier si le template est utilisé par des modèles
    try {
      const modelsData = await fsp.readFile(MODELS_FILE, "utf8");
      const models = JSON.parse(modelsData);
      if (models.some((m) => m.templateId === templateIdToDelete)) {
        return res.status(409).json({
          message:
            "Template en cours d'utilisation par des modèles et ne peut être supprimé.",
        });
      }
    } catch (e) {
      if (e.code !== "ENOENT") {
        console.warn(
          "Impossible de lire le fichier des modèles pour vérification des dépendances du template:",
          e
        );
        // Continuer avec prudence ou retourner une erreur ? Pour l'instant, on continue.
      }
    }

    let templates;
    try {
      const templatesData = await fsp.readFile(TEMPLATES_FILE, "utf8");
      templates = JSON.parse(templatesData);
    } catch (e) {
      if (e.code === "ENOENT")
        return res
          .status(404)
          .json({ message: "Fichier des templates non trouvé." });
      throw e;
    }

    const templateIndex = templates.findIndex(
      (t) => t.id === templateIdToDelete
    );
    if (templateIndex === -1)
      return res.status(404).json({ message: "Template non trouvé." });

    // Supprimer les entrées associées dans imagesTemplate.json
    try {
      let imagesTemplates;
      const imagesTemplatesData = await fsp.readFile(
        IMAGES_TEMPLATE_FILE,
        "utf8"
      );
      imagesTemplates = JSON.parse(imagesTemplatesData);
      const updatedImagesTemplates = imagesTemplates.filter(
        (it) => it.templateId !== templateIdToDelete
      );
      if (updatedImagesTemplates.length < imagesTemplates.length) {
        await fsp.writeFile(
          IMAGES_TEMPLATE_FILE,
          JSON.stringify(updatedImagesTemplates, null, 2)
        );
        console.log("Entrées imageTemplate associées au template supprimées.");
      }
    } catch (itError) {
      if (itError.code !== "ENOENT") {
        console.warn(
          "Erreur lors de la mise à jour de imagesTemplate.json pour le template supprimé:",
          itError
        );
      }
    }

    templates.splice(templateIndex, 1);
    await fsp.writeFile(TEMPLATES_FILE, JSON.stringify(templates, null, 2));

    res.json({ message: "Template supprimé avec succès." });
  } catch (error) {
    console.error(
      `Erreur lors de la suppression du template ${templateIdToDelete}:`,
      error
    );
    res
      .status(500)
      .json({ message: "Erreur serveur lors de la suppression du template." });
  }
});

//image template
app.get("/api/images-template", (req, res) => {
  const filePath = path.join(__dirname, "data", "imagesTemplate.json");
  try {
    const data = fs.readFileSync(filePath, "utf-8");
    const imagesTemplateData = JSON.parse(data);
    // Traiter les variables d'environnement dans les données
    const processedData = processEnvVars(imagesTemplateData);
    res.json(processedData);
  } catch (error) {
    console.error("Erreur lors de la lecture de imagesTemplate.json :", error);
    res.status(500).json({ error: "Impossible de lire imagesTemplate.json" });
  }
});
app.post("/api/add-images-template", (req, res) => {
  const dataPath = path.join(__dirname, "data", "imagesTemplate.json");

  const newData = req.body;

  if (!newData || typeof newData !== "object") {
    return res.status(400).json({ error: "Données invalides" });
  }

  // Lire le fichier actuel
  fs.readFile(dataPath, "utf8", (err, data) => {
    if (err) return res.status(500).json({ error: "Erreur lecture fichier" });

    let imagedata = [];
    try {
      imagedata = JSON.parse(data);
    } catch (e) {
      return res.status(500).json({ error: "Fichier JSON invalide" });
    }

    // Trouver le plus grand ID existant
    const lastId = imagedata.reduce((maxId, item) => {
      return item.id > maxId ? item.id : maxId;
    }, 0);

    // Assigner un nouvel ID
    const nextId = lastId + 1;
    const newEntry = { id: nextId, ...newData };

    // Ajouter la nouvelle donnée
    imagedata.push(newEntry);

    // Réécrire le fichier
    fs.writeFile(dataPath, JSON.stringify(imagedata, null, 2), (err) => {
      if (err)
        return res.status(500).json({ error: "Erreur écriture fichier" });
      res.json({ message: "Fichier mis à jour", newData });
    });
  });
});

/////////////////////////////////////
//canvas
/////////////////////////////////////
app.get("/api/canvas", (req, res) => {
  const filePath = path.join(__dirname, "data", "canvas.json");
  try {
    const data = fs.readFileSync(filePath, "utf-8");
    const canvasData = JSON.parse(data);
    // Traiter les variables d'environnement dans les données
    const processedData = processEnvVars(canvasData);
    res.json(processedData);
  } catch (error) {
    console.error("Erreur lors de la lecture de canvas.json :", error);
    res.status(500).json({ error: "Impossible de lire canvas.json" });
  }
});

app.get("/api/canvas/:id", (req, res) => {
  const canvasId = parseInt(req.params.id);
  fs.readFile(
    path.join(__dirname, "data", "canvas.json"),
    "utf8",
    (err, data) => {
      if (err) return res.status(500).json({ message: "Erreur serveur" });
      const canvasData = JSON.parse(data);
      const canvas = canvasData.find((canva) => canva.id === canvasId);
      if (!canvas)
        return res.status(404).json({ message: "Canvas non trouvé" });
      // Traiter les variables d'environnement dans le canvas
      const processedCanvas = processEnvVars(canvas);
      res.json(processedCanvas);
    }
  );
});

app.post("/api/add-canvas", (req, res) => {
  const dataPath = path.join(__dirname, "data", "canvas.json");

  const newData = req.body;

  if (!newData || typeof newData !== "object") {
    return res.status(400).json({ error: "Données invalides" });
  }

  // Lire le fichier actuel
  fs.readFile(dataPath, "utf8", (err, data) => {
    if (err) return res.status(500).json({ error: "Erreur lecture fichier" });

    let canvasdata = [];
    try {
      canvasdata = JSON.parse(data);
    } catch (e) {
      return res.status(500).json({ error: "Fichier JSON invalide" });
    }

    // Ajouter la nouvelle donnée
    canvasdata.push(newData);

    // Réécrire le fichier
    fs.writeFile(dataPath, JSON.stringify(canvasdata, null, 2), (err) => {
      if (err)
        return res.status(500).json({ error: "Erreur écriture fichier" });
      res.json({ message: "Fichier mis à jour", newData });
    });
  });
});

// Route pour supprimer un canvas
app.delete("/api/canvas/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Accès non autorisé." });
  }
  const canvasIdToDelete = parseInt(req.params.id, 10);

  try {
    // Vérifier si le canvas est utilisé par des modèles
    try {
      const modelsData = await fsp.readFile(MODELS_FILE, "utf8");
      const models = JSON.parse(modelsData);
      // Supposons que la liaison se fait via un champ comme model.canvasId ou model.dimensionId (si dimensionId réfère à un canvasId)
      // Adaptez la condition ci-dessous en fonction de la structure exacte de vos modèles
      if (
        models.some(
          (m) =>
            m.canvasId === canvasIdToDelete ||
            m.dimensionId === canvasIdToDelete
        )
      ) {
        return res.status(409).json({
          message:
            "Canvas en cours d'utilisation par des modèles et ne peut être supprimé.",
        });
      }
    } catch (e) {
      if (e.code !== "ENOENT") {
        console.warn(
          "Impossible de lire le fichier des modèles pour vérification des dépendances du canvas:",
          e
        );
      }
      // Si le fichier model.json n'existe pas, on peut supposer qu'il n'y a pas de dépendances.
    }

    let canvases;
    try {
      const canvasData = await fsp.readFile(CANVAS_FILE, "utf8");
      canvases = JSON.parse(canvasData);
    } catch (e) {
      if (e.code === "ENOENT")
        return res
          .status(404)
          .json({ message: "Fichier des canvas non trouvé." });
      throw e; // Pour les autres erreurs de lecture/parse
    }

    const canvasIndex = canvases.findIndex((c) => c.id === canvasIdToDelete);
    if (canvasIndex === -1)
      return res.status(404).json({ message: "Canvas non trouvé." });

    canvases.splice(canvasIndex, 1);
    await fsp.writeFile(CANVAS_FILE, JSON.stringify(canvases, null, 2));

    res.json({ message: "Canvas supprimé avec succès." });
  } catch (error) {
    console.error(
      `Erreur lors de la suppression du canvas ${canvasIdToDelete}:`,
      error
    );
    res
      .status(500)
      .json({ message: "Erreur serveur lors de la suppression du canvas." });
  }
});

///////////////////////////////////
//categories
/////////////////////////////////

// Configuration Multer pour les images d'en-tête de catégorie
const categoryHeaderStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Utiliser un dossier temporaire initialement
    const tempDir = path.join(UPLOAD_BASE_DIR, "tmp_category_headers");
    fs.mkdirSync(tempDir, { recursive: true });
    cb(null, tempDir);
  },
  filename: function (req, file, cb) {
    // Préfixer avec un timestamp pour éviter les collisions dans le dossier temporaire
    cb(null, Date.now() + "-" + file.originalname.replace(/\\s+/g, "_")); // Remplacer les espaces
  },
});

// Modifier pour accepter plusieurs champs de fichiers spécifiques
const uploadCategoryFiles = multer({
  storage: categoryHeaderStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // Limite de 5MB par fichier
  fileFilter: function (req, file, cb) {
    console.log("🔍 Filtrage du fichier:", file.originalname, file.mimetype);
    const filetypes = /jpeg|jpg|png|gif|webp/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    if (mimetype && extname) {
      console.log("✅ Fichier accepté:", file.originalname);
      return cb(null, true);
    }
    console.log("❌ Fichier rejeté:", file.originalname);
    cb(
      new Error(
        "Erreur : Seules les images (jpeg, jpg, png, gif, webp) sont autorisées !"
      )
    );
  },
}).fields([
  { name: "image", maxCount: 1 }, // Image principale
  { name: "imageRglt", maxCount: 1 }, // Image secondaire (réglementation ?)
]);

app.get("/api/categories", (req, res) => {
  const filePath = path.join(__dirname, "data", "categories.json");
  try {
    const data = fs.readFileSync(filePath, "utf-8");
    const categoriesData = JSON.parse(data);
    // Traiter les variables d'environnement dans les données
    const processedData = processEnvVars(categoriesData);
    res.json(processedData);
  } catch (error) {
    console.error("Erreur lors de la lecture de categories.json :", error);
    res.status(500).json({ error: "Impossible de lire categories.json" });
  }
});

app.get("/api/categories/:id", (req, res) => {
  const categoryId = parseInt(req.params.id);
  fs.readFile(
    path.join(__dirname, "data", "categories.json"),
    "utf8",
    (err, data) => {
      if (err) return res.status(500).json({ message: "Erreur serveur" });
      const categories = JSON.parse(data);
      const category = categories.find((cat) => cat.id === categoryId);
      if (!category)
        return res.status(404).json({ message: "Catégorie non trouvée" });
      // Traiter les variables d'environnement dans la catégorie
      const processedCategory = processEnvVars(category);
      res.json(processedCategory);
    }
  );
});

app.post(
  "/api/add-categories",
  authenticateToken,
  uploadCategoryFiles,
  async (req, res) => {
    // Vérifier le rôle de l'utilisateur (seulement super_admin peut ajouter)
    if (req.user.role !== "super_admin") {
      // Si un fichier a été uploadé dans tmp, le supprimer car accès refusé
      if (req.files?.image?.[0]?.path) {
        try {
          await fsp.unlink(req.files.image[0].path);
        } catch (e) {
          console.error("Erreur suppression tmp image:", e);
        }
      }
      if (req.files?.imageRglt?.[0]?.path) {
        try {
          await fsp.unlink(req.files.imageRglt[0].path);
        } catch (e) {
          console.error("Erreur suppression tmp imageRglt:", e);
        }
      }
      return res
        .status(403)
        .json({ message: "Accès non autorisé pour ajouter une catégorie." });
    }

    let newData;
    try {
      // Les données JSON sont attendues dans le champ 'data' du formulaire multipart
      if (!req.body.data) {
        if (req.files?.image?.[0]?.path) {
          try {
            await fsp.unlink(req.files.image[0].path);
          } catch (e) {}
        }
        if (req.files?.imageRglt?.[0]?.path) {
          try {
            await fsp.unlink(req.files.imageRglt[0].path);
          } catch (e) {}
        }
        return res.status(400).json({
          error:
            'Le champ "data" contenant les informations de la catégorie est manquant.',
        });
      }
      newData = JSON.parse(req.body.data);
    } catch (e) {
      if (req.files?.image?.[0]?.path) {
        try {
          await fsp.unlink(req.files.image[0].path);
        } catch (e) {}
      }
      if (req.files?.imageRglt?.[0]?.path) {
        try {
          await fsp.unlink(req.files.imageRglt[0].path);
        } catch (e) {}
      }
      return res.status(400).json({
        error: 'Données JSON invalides dans le champ "data".',
        details: e.message,
      });
    }

    // Validation simple des données reçues
    if (!newData || typeof newData !== "object" || !newData.name) {
      if (req.files?.image?.[0]?.path) {
        try {
          await fsp.unlink(req.files.image[0].path);
        } catch (e) {}
      }
      if (req.files?.imageRglt?.[0]?.path) {
        try {
          await fsp.unlink(req.files.imageRglt[0].path);
        } catch (e) {}
      }
      return res
        .status(400)
        .json({ error: "Données de catégorie invalides. Le nom est requis." });
    }

    // Récupérer les fichiers uploadés (s'ils existent)
    const mainImageFile = req.files?.image?.[0];
    const rgltImageFile = req.files?.imageRglt?.[0];

    try {
      let categories = [];
      try {
        const categoriesData = await fsp.readFile(CATEGORIES_FILE, "utf8");
        categories = JSON.parse(categoriesData);
      } catch (readError) {
        if (readError.code !== "ENOENT") {
          throw readError;
        }
        console.log(
          "categories.json non trouvé, initialisation avec un tableau vide."
        );
      }

      const lastId = categories.reduce(
        (maxId, item) => Math.max(maxId, item.id || 0),
        0
      );
      const nextId = lastId + 1;

      // Préparer l'entrée de la nouvelle catégorie
      const newEntry = {
        id: nextId,
        name: newData.name,
        image: null, // Sera mis à jour si l'image principale est uploadée
        imageRglt: null, // Sera mis à jour si l'image rglt est uploadée
        icon: newData.icon || null,
        shopIds: newData.shopIds || [],
        canvasId: newData.canvasId || null,
        canvas: newData.canvas || [],
        // Ajoutez d'autres champs par défaut ou issus de newData ici si nécessaire
        // Attention : ne pas copier aveuglément newData.image ou newData.imageRglt
        // car les chemins corrects sont déterminés ici.
      };

      const finalDestDir = path.join(
        UPLOAD_BASE_DIR,
        "categories",
        "headerPictures",
        String(nextId)
      );
      let imagePathForDb = null;
      let imageRgltPathForDb = null;

      // Gérer l'image principale si elle existe
      if (mainImageFile) {
        // Nettoyer le nom de fichier original (enlever le timestamp et remplacer espaces)
        const originalName = mainImageFile.filename
          .split("-")
          .slice(1)
          .join("-")
          .replace(/\s+/g, "_");
        const finalPath = path.join(finalDestDir, originalName);
        try {
          await fsp.mkdir(finalDestDir, { recursive: true });
          await fsp.rename(mainImageFile.path, finalPath);
          console.log(`Image principale déplacée vers: ${finalPath}`);
          // imagePathForDb = `${process.env.BASE_URL}uploads/categories/headerPictures/${nextId}/${originalName}`;
          imagePathForDb = `/uploads/categories/headerPictures/${nextId}/${originalName}`;
          newEntry.image = imagePathForDb;
          newEntry.canvas[0].src = imagePathForDb;
        } catch (moveError) {
          console.error(
            "Erreur lors du déplacement de l'image principale :",
            moveError
          );
          // Essayer de supprimer le fichier temporaire restant
          try {
            await fsp.unlink(mainImageFile.path);
          } catch (e) {
            console.error("Erreur suppression fichier tmp principal:", e);
          }
          // Si l'autre fichier a été uploadé, le supprimer aussi car l'opération échoue
          if (rgltImageFile?.path) {
            try {
              await fsp.unlink(rgltImageFile.path);
            } catch (e) {
              console.error("Erreur suppression fichier tmp rglt:", e);
            }
          }
          return res.status(500).json({
            error:
              "Erreur serveur lors de la sauvegarde de l'image principale.",
          });
        }
      }

      // Gérer l'image secondaire (rglt) si elle existe
      if (rgltImageFile) {
        const originalNameRglt = rgltImageFile.filename
          .split("-")
          .slice(1)
          .join("-")
          .replace(/\s+/g, "_");
        const finalPathRglt = path.join(finalDestDir, originalNameRglt);
        try {
          // Le dossier a peut-être déjà été créé par l'image principale
          await fsp.mkdir(finalDestDir, { recursive: true });
          await fsp.rename(rgltImageFile.path, finalPathRglt);
          console.log(`Image Rglt déplacée vers: ${finalPathRglt}`);
          // imageRgltPathForDb = `${process.env.BASE_URL}uploads/categories/headerPictures/${nextId}/${originalNameRglt}`;
          imageRgltPathForDb = `/uploads/categories/headerPictures/${nextId}/${originalNameRglt}`;
          newEntry.imageRglt = imageRgltPathForDb;
          newEntry.canvas[0].srcRglt = imageRgltPathForDb;
        } catch (moveError) {
          console.error(
            "Erreur lors du déplacement de l'image Rglt :",
            moveError
          );
          try {
            await fsp.unlink(rgltImageFile.path);
          } catch (e) {
            console.error("Erreur suppression fichier tmp rglt:", e);
          }
          // Si l'image principale a été déplacée avec succès mais celle-ci échoue, faut-il annuler ?
          // Pour l'instant, on retourne une erreur et on ne sauvegarde pas la catégorie.
          // On pourrait aussi essayer de supprimer l'image principale déjà déplacée.
          if (newEntry.image) {
            // Si l'image principale a été déplacée
            const mainImageFinalPath = path.join(
              finalDestDir,
              path.basename(newEntry.image)
            );
            try {
              await fsp.unlink(mainImageFinalPath);
              console.log("Image principale annulée supprimée.");
            } catch (e) {}
          }
          return res.status(500).json({
            error:
              "Erreur serveur lors de la sauvegarde de l'image secondaire.",
          });
        }
      }

      // Ajouter la nouvelle catégorie (avec les chemins d'image mis à jour)
      categories.push(newEntry);

      // Réécrire le fichier categories.json
      await fsp.writeFile(CATEGORIES_FILE, JSON.stringify(categories, null, 2));

      // Retourner la catégorie créée avec les chemins corrects
      res.status(201).json({
        message: "Catégorie ajoutée avec succès.",
        category: newEntry,
      });
    } catch (error) {
      console.error(
        "Erreur lors de l'ajout de la catégorie (catch principal) :",
        error
      );
      // Nettoyage final des fichiers temporaires si une erreur autre s'est produite
      if (mainImageFile?.path) {
        try {
          await fsp.unlink(mainImageFile.path);
        } catch (e) {
          /* Ignorer */
        }
      }
      if (rgltImageFile?.path) {
        try {
          await fsp.unlink(rgltImageFile.path);
        } catch (e) {
          /* Ignorer */
        }
      }
      res
        .status(500)
        .json({ error: "Erreur serveur lors de l'ajout de la catégorie." });
    }
  }
);


// Route pour modifier une catégorie
app.patch("/api/categories/:id", authenticateToken, uploadCategoryFiles, async (req, res) => {
  console.log("🚀 Route PATCH /api/categories/:id appelée");
  console.log("📁 Fichiers reçus:", req.files);
  console.log("📝 Body reçu:", req.body);
  
  if (req.user.role !== "super_admin") {
    return res
      .status(403)
      .json({ message: "Accès non autorisé pour modifier une catégorie." });
  }

  const categoryIdToUpdate = parseInt(req.params.id, 10);
  let updates;
  
  try {
    updates = JSON.parse(req.body.data);
  } catch (e) {
    return res.status(400).json({
      error: 'Données JSON invalides dans le champ "data".',
      details: e.message,
    });
  }

  if (isNaN(categoryIdToUpdate)) {
    return res.status(400).json({ message: "ID de catégorie invalide." });
  }

  if (Object.keys(updates)?.length === 0 && !req.files) {
    return res
      .status(400)
      .json({ message: "Aucune donnée de mise à jour fournie." });
  }

  // Interdire la modification de l'ID
  if (updates.hasOwnProperty("id")) {
    return res.status(400).json({
      message: "La modification de l'ID de la catégorie n'est pas autorisée.",
    });
  }

  try {
    let categories;
    try {
      const categoriesData = await fsp.readFile(CATEGORIES_FILE, "utf8");
      categories = JSON.parse(categoriesData);
    } catch (readError) {
      if (readError.code === "ENOENT") {
        return res
          .status(404)
          .json({ message: "Fichier des catégories non trouvé." });
      }
      console.error("Erreur lecture ou parse categories.json:", readError);
      return res.status(500).json({
        message:
          "Erreur serveur lors de la lecture des données des catégories.",
      });
    }

    const categoryIndex = categories.findIndex(
      (c) => c.id === categoryIdToUpdate
    );

    if (categoryIndex === -1) {
      return res.status(404).json({ message: "Catégorie non trouvée." });
    }

    // Appliquer les mises à jour
    const categoryToUpdate = { ...categories[categoryIndex] };
    const allowedFields = [
      "name",
      "icon",
      "shopIds",
      "canvasId",
      "canvas",
    ];
    let Patcher = false;
    let imageUpdated = false;
    let imageRgltUpdated = false;

    // Traiter les champs de données
    for (const field of allowedFields) {
      if (updates.hasOwnProperty(field)) {
        categoryToUpdate[field] = updates[field];
        Patcher = true;
      }
    }

    // Traiter les fichiers uploadés
    const finalDestDir = path.join(
      UPLOAD_BASE_DIR,
      "categories",
      "headerPictures",
      String(categoryIdToUpdate)
    );

    // Gérer l'image principale si elle a été uploadée
    if (req.files?.image?.[0]) {
      const mainImageFile = req.files.image[0];
      const originalName = mainImageFile.filename
        .split("-")
        .slice(1)
        .join("-")
        .replace(/\s+/g, "_");
      
      try {
        await fsp.mkdir(finalDestDir, { recursive: true });
        const finalPath = path.join(finalDestDir, originalName);
        await fsp.rename(mainImageFile.path, finalPath);
        
        const imagePathForDb = `/uploads/categories/headerPictures/${categoryIdToUpdate}/${originalName}`;
        categoryToUpdate.image = imagePathForDb;
        
        // Mettre à jour le canvas de la catégorie si il existe
        if (categoryToUpdate.canvas && Array.isArray(categoryToUpdate.canvas) && categoryToUpdate.canvas[0]) {
          categoryToUpdate.canvas[0].src = imagePathForDb;
        }
        
        imageUpdated = true;
        Patcher = true;
        console.log(`Image principale mise à jour: ${finalPath}`);
      } catch (moveError) {
        console.error("Erreur lors de la mise à jour de l'image principale:", moveError);
        // Nettoyer le fichier temporaire
        try {
          await fsp.unlink(mainImageFile.path);
        } catch (e) {}
        return res.status(500).json({
          error: "Erreur serveur lors de la sauvegarde de l'image principale.",
        });
      }
    }

    // Gérer l'image secondaire si elle a été uploadée
    if (req.files?.imageRglt?.[0]) {
      const rgltImageFile = req.files.imageRglt[0];
      const originalNameRglt = rgltImageFile.filename
        .split("-")
        .slice(1)
        .join("-")
        .replace(/\s+/g, "_");
      
      try {
        await fsp.mkdir(finalDestDir, { recursive: true });
        const finalPathRglt = path.join(finalDestDir, originalNameRglt);
        await fsp.rename(rgltImageFile.path, finalPathRglt);
        
        const imageRgltPathForDb = `/uploads/categories/headerPictures/${categoryIdToUpdate}/${originalNameRglt}`;
        categoryToUpdate.imageRglt = imageRgltPathForDb;
        
        // Mettre à jour le canvas de la catégorie si il existe
        if (categoryToUpdate.canvas && Array.isArray(categoryToUpdate.canvas) && categoryToUpdate.canvas[0]) {
          categoryToUpdate.canvas[0].srcRglt = imageRgltPathForDb;
        }
        
        imageRgltUpdated = true;
        Patcher = true;
        console.log(`Image secondaire mise à jour: ${finalPathRglt}`);
      } catch (moveError) {
        console.error("Erreur lors de la mise à jour de l'image secondaire:", moveError);
        // Nettoyer le fichier temporaire
        try {
          await fsp.unlink(rgltImageFile.path);
        } catch (e) {}
        return res.status(500).json({
          error: "Erreur serveur lors de la sauvegarde de l'image secondaire.",
        });
      }
    }

    if (!Patcher) {
      return res
        .status(400)
        .json({ message: "Aucun champ valide à mettre à jour fourni." });
    }

    // Marquer que des mises à jour canvas ont été effectuées
    let canvasUpdated = updates.hasOwnProperty("canvas");

    // Si les images ont été modifiées ou si des champs canvas ont été modifiés, mettre à jour les modèles associés
    if (imageUpdated || imageRgltUpdated || updates.hasOwnProperty("canvas")) {
      try {
        const modelsData = await fsp.readFile(MODELS_FILE, "utf8");
        const models = JSON.parse(modelsData);
        
        // Trouver tous les modèles associés à cette catégorie
        const modelsToUpdate = models.filter(m => m.categoryId === categoryIdToUpdate);
        
        if (modelsToUpdate.length > 0) {
          // Mettre à jour chaque modèle
          for (const model of modelsToUpdate) {
            if (model.canvas && Array.isArray(model.canvas)) {
              // Parcourir tous les éléments du canvas
              for (const canvasElement of model.canvas) {
                if (canvasElement.type === "header") {
                  // Mettre à jour l'image principale si elle a été modifiée
                  if (imageUpdated && categoryToUpdate.image) {
                    canvasElement.src = categoryToUpdate.image;
                  }
                  
                  // Mettre à jour l'image secondaire si elle a été modifiée
                  if (imageRgltUpdated && categoryToUpdate.imageRglt) {
                    canvasElement.srcRglt = categoryToUpdate.imageRglt;
                  }
                  
                  // Mettre à jour les autres propriétés du header (comme backgroundColor) si elles ont été modifiées
                  if (updates.hasOwnProperty("canvas") && updates.canvas && Array.isArray(updates.canvas) && updates.canvas[0]) {
                    const updatedHeader = updates.canvas[0];
                    if (updatedHeader.backgroundColor !== undefined) {
                      canvasElement.backgroundColor = updatedHeader.backgroundColor;
                    }
                    if (updatedHeader.color !== undefined) {
                      canvasElement.color = updatedHeader.color;
                    }
                    if (updatedHeader.fontSize !== undefined) {
                      canvasElement.fontSize = updatedHeader.fontSize;
                    }
                    if (updatedHeader.fontFamily !== undefined) {
                      canvasElement.fontFamily = updatedHeader.fontFamily;
                    }
                    if (updatedHeader.textAlign !== undefined) {
                      canvasElement.textAlign = updatedHeader.textAlign;
                    }
                    if (updatedHeader.padding !== undefined) {
                      canvasElement.padding = updatedHeader.padding;
                    }
                    if (updatedHeader.margin !== undefined) {
                      canvasElement.margin = updatedHeader.margin;
                    }
                    if (updatedHeader.borderRadius !== undefined) {
                      canvasElement.borderRadius = updatedHeader.borderRadius;
                    }
                    if (updatedHeader.border !== undefined) {
                      canvasElement.border = updatedHeader.border;
                    }
                    if (updatedHeader.boxShadow !== undefined) {
                      canvasElement.boxShadow = updatedHeader.boxShadow;
                    }
                  }
                }
                
                // Mettre à jour les éléments de type "background-color" si le canvas a été modifié
                if (canvasElement.type === "background-color" && updates.hasOwnProperty("canvas") && updates.canvas && Array.isArray(updates.canvas)) {
                  // Chercher l'élément background-color correspondant dans les mises à jour
                  const updatedBackground = updates.canvas.find(el => el.type === "background-color");
                  if (updatedBackground) {
                    if (updatedBackground.backgroundColor !== undefined) {
                      canvasElement.backgroundColor = updatedBackground.backgroundColor;
                    }
                    if (updatedBackground.opacity !== undefined) {
                      canvasElement.opacity = updatedBackground.opacity;
                    }
                    if (updatedBackground.gradient !== undefined) {
                      canvasElement.gradient = updatedBackground.gradient;
                    }
                  }
                }
              }
            }
          }
          
          // Sauvegarder les modèles mis à jour
          await fsp.writeFile(MODELS_FILE, JSON.stringify(models, null, 2));
          console.log(`${modelsToUpdate.length} modèles mis à jour pour la catégorie ${categoryIdToUpdate}`);
        }
      } catch (e) {
        if (e.code !== "ENOENT") {
          console.warn("Erreur lors de la mise à jour des modèles associés:", e);
        }
      }
    }

    categories[categoryIndex] = categoryToUpdate;

    await fsp.writeFile(CATEGORIES_FILE, JSON.stringify(categories, null, 2));

    res.json({
      message: "Catégorie mise à jour avec succès.",
      category: categoryToUpdate,
      modelsUpdated: imageUpdated || imageRgltUpdated || canvasUpdated ? true : false,
      updatesApplied: {
        images: imageUpdated || imageRgltUpdated,
        canvas: canvasUpdated
      }
    });
  } catch (error) {
    console.error(
      `Erreur lors de la mise à jour de la catégorie ${categoryIdToUpdate}:`,
      error
    );
    // Nettoyer les fichiers temporaires en cas d'erreur
    if (req.files?.image?.[0]?.path) {
      try {
        await fsp.unlink(req.files.image[0].path);
      } catch (e) {}
    }
    if (req.files?.imageRglt?.[0]?.path) {
      try {
        await fsp.unlink(req.files.imageRglt[0].path);
      } catch (e) {}
    }
    res.status(500).json({
      message: "Erreur serveur lors de la mise à jour de la catégorie.",
    });
  }
});

// Route pour supprimer une catégorie
app.delete("/api/categories/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Accès non autorisé." });
  }
  const categoryIdToDelete = parseInt(req.params.id, 10);

  try {
    let categories;
    try {
      const categoriesData = await fsp.readFile(CATEGORIES_FILE, "utf8");
      categories = JSON.parse(categoriesData);
    } catch (e) {
      if (e.code === "ENOENT")
        return res
          .status(404)
          .json({ message: "Fichier des catégories non trouvé." });
      throw e;
    }

    const categoryIndex = categories.findIndex(
      (c) => c.id === categoryIdToDelete
    );
    if (categoryIndex === -1)
      return res.status(404).json({ message: "Catégorie non trouvée." });

    const categoryToDelete = categories[categoryIndex]; // Récupérer l'objet catégorie

    // Supprimer tous les modèles associés à cette catégorie
    try {
      const modelsData = await fsp.readFile(MODELS_FILE, "utf8");
      const models = JSON.parse(modelsData);
      
      // Filtrer les modèles à supprimer
      const modelsToDelete = models.filter(m => m.categoryId === categoryIdToDelete);
      const remainingModels = models.filter(m => m.categoryId !== categoryIdToDelete);
      
      // Supprimer les miniatures des modèles supprimés
      for (const model of modelsToDelete) {
        if (model.image && model.categoryId) {
          const imagePath = path.join(
            __dirname,
            "uploads",
            "miniatures",
            String(model.categoryId),
            model.image
          );
          try {
            await fsp.unlink(imagePath);
            console.log(`Miniature supprimée: ${imagePath}`);
          } catch (unlinkError) {
            if (unlinkError.code !== "ENOENT") {
              console.warn(`Erreur lors de la suppression de la miniature ${imagePath}:`, unlinkError);
            }
          }
        }
      }
      
      // Sauvegarder la liste des modèles mise à jour
      await fsp.writeFile(MODELS_FILE, JSON.stringify(remainingModels, null, 2));
      console.log(`${modelsToDelete.length} modèles supprimés pour la catégorie ${categoryIdToDelete}`);
      
    } catch (e) {
      if (e.code !== "ENOENT") {
        console.warn("Erreur lors de la suppression des modèles associés:", e);
      }
    }

    // Supprimer tous les templates associés à cette catégorie
    try {
      const templatesData = await fsp.readFile(TEMPLATES_FILE, "utf8");
      const templates = JSON.parse(templatesData);
      
      // Filtrer les templates à supprimer
      const templatesToDelete = templates.filter(t => t.categoryId === categoryIdToDelete);
      const remainingTemplates = templates.filter(t => t.categoryId !== categoryIdToDelete);
      
      // Sauvegarder la liste des templates mise à jour
      await fsp.writeFile(TEMPLATES_FILE, JSON.stringify(remainingTemplates, null, 2));
      console.log(`${templatesToDelete.length} templates supprimés pour la catégorie ${categoryIdToDelete}`);
      
    } catch (e) {
      if (e.code !== "ENOENT") {
        console.warn("Erreur lors de la suppression des templates associés:", e);
      }
    }

    // Supprimer toutes les entrées imageTemplate associées aux templates supprimés
    try {
      const imagesTemplateData = await fsp.readFile(IMAGES_TEMPLATE_FILE, "utf8");
      const imagesTemplates = JSON.parse(imagesTemplateData);
      
      // Récupérer les IDs des templates supprimés pour identifier les imageTemplate à supprimer
      let templatesToDeleteIds = [];
      try {
        const templatesData = await fsp.readFile(TEMPLATES_FILE, "utf8");
        const allTemplates = JSON.parse(templatesData);
        templatesToDeleteIds = allTemplates
          .filter(t => t.categoryId === categoryIdToDelete)
          .map(t => t.id);
      } catch (e) {
        // Si on ne peut pas lire les templates, on utilise une approche différente
        // On supprime les imageTemplate qui ont des noms correspondant aux modèles supprimés
      }
      
      // Supprimer les imageTemplate associés aux templates de cette catégorie
      const remainingImagesTemplates = imagesTemplates.filter(it => 
        !templatesToDeleteIds.includes(it.templateId)
      );
      
      if (remainingImagesTemplates.length < imagesTemplates.length) {
        await fsp.writeFile(IMAGES_TEMPLATE_FILE, JSON.stringify(remainingImagesTemplates, null, 2));
        console.log(`${imagesTemplates.length - remainingImagesTemplates.length} entrées imageTemplate supprimées`);
      }
      
    } catch (e) {
      if (e.code !== "ENOENT") {
        console.warn("Erreur lors de la suppression des imageTemplate associés:", e);
      }
    }

    // Supprimer la catégorie
    categories.splice(categoryIndex, 1);
    await fsp.writeFile(CATEGORIES_FILE, JSON.stringify(categories, null, 2));

    // Supprimer le dossier des images d'en-tête de catégorie
    const categoryHeaderPath = path.join(
      UPLOAD_BASE_DIR,
      "categories",
      "headerPictures",
      String(categoryIdToDelete)
    );
    try {
      await fsp.rm(categoryHeaderPath, { recursive: true, force: true });
      console.log(
        `Dossier d'images d'en-tête de catégorie supprimé: ${categoryHeaderPath}`
      );
    } catch (rmError) {
      if (rmError.code !== "ENOENT") {
        console.warn(
          `Erreur lors de la suppression du dossier ${categoryHeaderPath}:`,
          rmError
        );
      }
    }

    // Supprimer le dossier de miniatures de catégorie
    const categoryMiniaturesPath = path.join(
      __dirname,
      "uploads",
      "miniatures",
      String(categoryIdToDelete)
    );
    try {
      await fsp.rm(categoryMiniaturesPath, { recursive: true, force: true });
      console.log(
        `Dossier de miniatures de catégorie supprimé: ${categoryMiniaturesPath}`
      );
    } catch (rmError) {
      if (rmError.code !== "ENOENT") {
        console.warn(
          `Erreur lors de la suppression du dossier de miniatures ${categoryMiniaturesPath}:`,
          rmError
        );
      }
    }

    // Supprimer le dossier des images de catégorie
    const categoryImagesPath = path.join(
      UPLOAD_BASE_DIR,
      "categories",
      "images",
      String(categoryIdToDelete)
    );
    try {
      await fsp.rm(categoryImagesPath, { recursive: true, force: true });
      console.log(
        `Dossier d'images de catégorie supprimé: ${categoryImagesPath}`
      );
    } catch (rmError) {
      if (rmError.code !== "ENOENT") {
        console.warn(
          `Erreur lors de la suppression du dossier d'images ${categoryImagesPath}:`,
          rmError
        );
      }
    }

    res.json({ 
      message: "Catégorie et tous ses éléments associés supprimés avec succès.",
      deletedModels: modelsToDelete?.length || 0,
      deletedTemplates: templatesToDelete?.length || 0
    });
  } catch (error) {
    console.error(
      `Erreur lors de la suppression de la catégorie ${categoryIdToDelete}:`,
      error
    );
    res.status(500).json({
      message: "Erreur serveur lors de la suppression de la catégorie.",
    });
  }
});

//////////////////////////
// Shops
//////////////////////////
// Définit le chemin complet du dossier où seront stockées les miniatures de la boutique
const uploadShopMiniatureDir = path.join(
  __dirname,
  "uploads",
  "shopMiniatures"
);
// Vérifie si le dossier existe déjà
if (!fs.existsSync(uploadShopMiniatureDir)) {
  // S'il n'existe pas, on le crée (de manière synchrone)
  fs.mkdirSync(uploadShopMiniatureDir);
}

// Configure le stockage pour multer (gestion des fichiers uploadés)
const shopMiniatureStorage = multer.diskStorage({
  // Spécifie le dossier de destination pour enregistrer les fichiers
  destination: (req, file, cb) => {
    cb(null, uploadShopMiniatureDir); // on utilise le dossier défini plus haut
  },
  // Définit le nom de fichier utilisé lors de l'enregistrement
  filename: (req, file, cb) => {
    cb(null, file.originalname); // le fichier conserve son nom d'origine
  },
});

// Initialise l'instance de multer avec la configuration de stockage définie
const uploadShopMiniature = multer({ storage: shopMiniatureStorage });

app.get("/api/shops", (req, res) => {
  const filePath = path.join(__dirname, "data", "shops.json");
  try {
    const data = fs.readFileSync(filePath, "utf-8");
    const shopsData = JSON.parse(data);
    // Traiter les variables d'environnement dans les données
    const processedData = processEnvVars(shopsData);
    res.json(processedData);
  } catch (error) {
    console.error("Erreur lors de la lecture de shops.json :", error);
    res.status(500).json({ error: "Impossible de lire shops.json" });
  }
});

app.post("/api/add-shop", uploadShopMiniature.single("image"), (req, res) => {
  const dataPath = path.join(__dirname, "data", "shops.json");
  const uploadDir = path.join(__dirname, "uploads", "shopMiniatures");

  let newData;
  try {
    newData = JSON.parse(req.body.data); // envoyer le JSON en champ `data`
  } catch (e) {
    return res.status(400).json({ error: "Données invalides" });
  }

  fs.readFile(dataPath, "utf8", (err, shopFileContent) => {
    if (err) return res.status(500).json({ error: "Erreur lecture fichier" });

    let shopData = [];
    try {
      shopData = JSON.parse(shopFileContent);
    } catch (e) {
      return res.status(500).json({ error: "Fichier JSON invalide" });
    }

    const lastShopId = shopData.reduce(
      (maxId, item) => (item.id > maxId ? item.id : maxId),
      0
    );
    const nextId = lastShopId + 1;

    const newEntry = { id: nextId, ...newData };

    shopData.push(newEntry);

    // Crée un dossier pour les miniatures de ce shop
    const shopName = newData.name;
    const shopDir = path.join(uploadDir, shopName);
    fs.mkdirSync(shopDir, { recursive: true });

    // Déplace le fichier vers le bon dossier
    if (req.file) {
      // const imgName = `/uploads/shopMiniatures/${newData.name}/${req.file.originalname}`
      // const targetPath = path.join(shopDir, imgName)
      const targetPath = path.join(shopDir, req.file.originalname);
      fs.rename(req.file.path, targetPath, (err) => {
        if (err)
          return res.status(500).json({ error: "Erreur déplacement image" });
        // Écrire le fichier JSON après le déplacement réussi
        fs.writeFile(dataPath, JSON.stringify(shopData, null, 2), (err) => {
          if (err)
            return res.status(500).json({ error: "Erreur écriture fichier" });
          res.json({
            message: "Shop ajouté avec miniature",
            newData: newEntry,
          });
        });
      });
    } else {
      fs.writeFile(dataPath, JSON.stringify(shopData, null, 2), (err) => {
        if (err)
          return res.status(500).json({ error: "Erreur écriture fichier" });
        res.json({
          message: "Shop ajouté (sans miniature)",
          newData: newEntry,
        });
      });
    }
  });
});

// Route pour supprimer une boutique (shop)
app.delete("/api/shops/:id", authenticateToken, async (req, res) => {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({ message: "Accès non autorisé." });
  }
  const shopIdToDelete = parseInt(req.params.id, 10);

  try {
    let shops;
    try {
      const shopsData = await fsp.readFile(SHOPS_FILE, "utf8");
      shops = JSON.parse(shopsData);
    } catch (e) {
      if (e.code === "ENOENT")
        return res
          .status(404)
          .json({ message: "Fichier des boutiques non trouvé." });
      throw e;
    }

    const shopIndex = shops.findIndex((s) => s.id === shopIdToDelete);
    if (shopIndex === -1)
      return res.status(404).json({ message: "Boutique non trouvée." });

    const shopToDelete = shops[shopIndex];

    shops.splice(shopIndex, 1);
    await fsp.writeFile(SHOPS_FILE, JSON.stringify(shops, null, 2));

    // Supprimer le dossier de miniatures associé à la boutique
    if (shopToDelete.name) {
      // Le dossier est nommé d'après shop.name
      const shopMiniaturePath = path.join(
        __dirname,
        "uploads",
        "shopMiniatures",
        shopToDelete.name
      );
      try {
        await fsp.rm(shopMiniaturePath, { recursive: true, force: true });
        console.log(
          `Dossier de miniatures de boutique supprimé: ${shopMiniaturePath}`
        );
      } catch (rmError) {
        if (rmError.code !== "ENOENT") {
          // Ne pas avertir si le dossier n'existait simplement pas
          console.warn(
            `Erreur lors de la suppression du dossier de miniatures de la boutique ${shopMiniaturePath}:`,
            rmError
          );
        }
      }
    }

    res.json({ message: "Boutique supprimée avec succès." });
  } catch (error) {
    console.error(
      `Erreur lors de la suppression de la boutique ${shopIdToDelete}:`,
      error
    );
    res.status(500).json({
      message: "Erreur serveur lors de la suppression de la boutique.",
    });
  }
});

//////////////////////////
// Upload d'images
//////////////////////////
// Dossier de destination
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Configuration de multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir); // Destination des fichiers
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage });

// Route d'upload
app.post("/api/upload", upload.single("image"), (req, res) => {
  if (!req.file || req.files?.length === 0) {
    return res.status(400).json({ message: "Aucun fichier reçu." });
  }
  res.json({
    message: "Image uploadée avec succès !",
    filename: req.file.filename,
  });
});

// Middleware Multer (dossier créé dynamiquement avec l'ID)
const storageImgCat = multer.diskStorage({
  destination: function (req, file, cb) {
    const categoryId = req.params.id;
    const dir = path.join(uploadDir, "categories", "images", categoryId);

    // Crée le dossier s'il n'existe pas
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});

const uploadImgCat = multer({ storage: storageImgCat });

// Route pour uploader plusieurs images dans le dossier de la catégorie
app.post("/api/uploads/:id", uploadImgCat.array("images", 10), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: "Aucun fichier reçu" });
  }

  const fileInfos = req.files.map((file) => ({
    filename: file.filename,
    path: `/uploads/categories/images/${req.params.id}/${file.filename}`,
  }));

  res.status(200).json({ message: "Images uploadées", files: fileInfos });
});

app.get("/api/uploads/:id", (req, res) => {
  const categoryId = req.params.id;
  const dirPath = path.join(
    UPLOAD_BASE_DIR,
    "categories",
    "images",
    categoryId
  );

  fs.readdir(dirPath, (err, files) => {
    if (err) {
      // Si le dossier spécifique n'existe pas, retourner un tableau vide plutôt qu'une erreur 404
      if (err.code === "ENOENT") {
        return res.json({ images: [] });
      }
      return res
        .status(500)
        .json({ error: "Erreur lors de la lecture du dossier des images." });
    }

    // Adapter le chemin retourné
    const imagePaths = files.map(
      (file) => `/uploads/categories/images/${categoryId}/${file}`
    );
    res.json({ images: imagePaths });
  });
});

app.delete("/api/uploads/:id/:filename", (req, res) => {
  const { id, filename } = req.params;
  // Adapter le chemin pour chercher dans le sous-dossier 'images'
  const filePath = path.join(
    UPLOAD_BASE_DIR,
    "categories",
    "images",
    id,
    filename
  );

  fs.unlink(filePath, (err) => {
    if (err) {
      console.error("Erreur suppression fichier :", err);
      return res
        .status(404)
        .json({ error: "Fichier introuvable ou déjà supprimé" });
    }
    res.json({ message: "Image supprimée avec succès" });
  });
});

// Pour accéder aux fichiers uploadés depuis le navigateur
// S'assurer que cela sert bien TOUT le dossier 'uploads'
app.use("/uploads", express.static(UPLOAD_BASE_DIR));

app.listen(PORT, () =>
  console.log(`Serveur backend lancé sur http://localhost:${PORT}`)
);
