const Authentication = require('./controllers/authentication');
const passportService = require('./services/passport');
const passport = require('passport');

const requireAuth = passport.authenticate('jwt', { session: false });
const requireSignin = passport.authenticate('local', { session: false });

module.exports = function(app) {
  //
  app.get('/', requireAuth, function(req, res) {
    res.send({ hi: 'there' });
  });
  app.post('/signin', requireSignin, Authentication.signin);
  app.post('/signup', Authentication.signup);
};

//on définit un nouveau gestionnaire de route pour gérer a get request to our route route
//on dit n'inmporte quelle requette qui arrive dans cette route, elle doit d'abord
//passer par cette condition requise ou cette étape obligée(requireAuth), seulement après, il peut aller jusqu'au gestionnaire de requêtte

//app.get('/', requireAuth, function(req, res) {
//res.send({ hi: 'there' });});
