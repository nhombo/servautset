//passport est un library nous permet de savoir si un user est authentifié ou non à notre application dans une Strategy qui tente d'authentifier ce user d'une façon particulière
//  nous aidera authentifier un user quand il essai d'accéder à une ressource qui requiert authentification
//passport n'est pas juste une library, c'est plus un ecosystem. Cet ecosystem est formé par ce qu'on appelle ou est référencé comme stragégies.
//Une stratégie passport est une methode servant à authentifier un user, c'est un plugin qui travail avec passport. passport-jwt tente de valider ou authentifier a user en utilisant un jason web token(JWT).
//On pourrait aussi installer une Strategie qui pourrait tenter de vérifier un user qui a fourni a username et password.
// Il y a beaubeaup beaucoup de Strategies passport qui existe(pour gérer le login ave Facebook, ou Twitter, ou Github, ou Google) géré par ce plugin passport
const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

const LocalStrategy = require('passport-local');
const localOptions = { usernameField: 'email' };

//creation local Strategy
const localLogin = new LocalStrategy(localOptions, function(
  email,
  password,
  done
) {
  //on verifie que le email et le password, call done avec le user
  //si email et password sont corrects
  //otherwise, call done with false
  //ainsi donc on trouve un user existant dans la database, et on compare le password fourni avec le password sauvegardé ou enregistré,
  //on les compare, si c'est le même, on appelle le passport callback avec le user model, sinon on retourne désolé pas correspond
  User.findOne({ email: email }, function(err, user) {
    if (err) {
      return done(err);
    }
    if (!user) {
      return done(null, false);
    }
    //compare passwords - is password equal to user.password ?
    // on compore si le password fourni dans la requette correspond à notre password enregistré en base
    //user est celui trouvé en base
    //ainsi donc on
    user.comparePassword(password, function(err, isMatch) {
      if (err) {
        return done(err);
      }
      if (!isMatch) {
        return done(null, false);
      }
      //done callback est founi par passport qui prend ce user model l'assigne à req.user
      return done(null, user);
    });
  });
});

//Setup options for JWT Strategy
//car l'obtion payload dans jwtLogin qui represente jwt token avec sub: userid et iat: timestamp peut être partout
//soit il peut se trouver dans l'entête, le corp, dans l'url de la requete, donc on doit spéfier Strategy où trouver dans la  requete cet clé
const jwtOptions = {
  // pour cela , on indique au Strategy de regarder dans l'entête et spécialement a header appelé 'authorization' pour trouver ce token.
  //on donne un deuxième argument pour indiquer la cle qui aide à décoder
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

//on utilise jwt Strategy pour nous aider dans jwt authentication et passport
//Create JWT Strategy
//le payload le decoding jwt token - c'est ce qu'on installé avec sub: user et issue ce timestamp et iat dans le controller authentication => c'était le tokens payload
//et donc quand on a le payload de retour ou back ou retourné, ce payload est le userid et timestamp dans la Strategy de JwtStrategy.
//Donc ici on est dans le cas qu'on doit décoder ce token représenté par payload
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  //voir si le user ID dans le payload exists dans notre base de données
  //Si c'est le cas, call 'done' avec that other
  //sinon - othewilse, call done without a user object
  //Donc si on trouve avec succès un user avec cet ID donné avec le token, on le passe à cette 'done' callback :function(payload, done) comme partie de passport et
  //laisse passport savoir qui est ce user
  // => dans ce cas on a authentifié le user, il a la permissoin d'avoir accès aux ressources
  //par contre si on peut pas trouver ce user avec cet ID, on appelle la fonction 'done' sans a user object qui indique que cette personne n'est pas authentifiée,
  //donc pas valide
  User.findById(payload.sub, function(err, user) {
    //err renvoi des erreur de connexion qui passe pas etc ...
    if (err) {
      return done(err, false);
    }
    if (user) {
      done(null, user);
    } else {
      done(null, false);
    }
  });
});

//on demande à passport be sur to use this Strategy
passport.use(jwtLogin);
passport.use(localLogin);
