const jwt = require('jsonwebtoken')
const JWT_SECRET = 'votre_cle_secrete_à_bien_protéger'

// function authenticateToken(req, res, next) {
//   const authHeader = req.headers['authorization']
//   const token = authHeader && authHeader.split(' ')[1]

//   if (!token) return res.status(401).json({ error: 'Token manquant' })

//   verify(token, JWT_SECRET, (err, user) => {
//     if (err) return res.status(403).json({ error: 'Token invalide' })
//     req.user = user
//     next()
//   })
// }
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1]
    if (!token) return res.sendStatus(401)
  
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) return res.sendStatus(403)
  
      const users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'))
      const user = users.find(u => u.id === decoded.id)
      if (!user) return res.sendStatus(404)
  
      req.user = user
      next()
    })
  }

export default authenticateToken