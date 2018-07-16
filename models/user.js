const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');
//définir notre model
const userSchema = new Schema({
  email: { type: String, unique: true, lowercase: true },
  password: String
});

//On save Hook, encrypt password
//Before saving a model, run this function
userSchema.pre('save', function(next) {
  //get access to the user model
  const user = this; //dans ce context user est une instance de user model. => user.email, user.password

  //pour générer un salt then run callback
  //1) on génère un salt
  bcrypt.genSalt(10, function(err, salt) {
    if (err) {
      return next(err);
    }
    //un salt est une chaine de caractère ou caracteres généré de façon aléatoire. En combinant  un salt et un plain password, on obtient un hached ou encrypted password
    //le long string obtenu contient et salt et hash ou encrypted password
    //hash ou encrypt notre password usign the salt et le resultat est un hash(qui est un password encrypté).
    //2)on prend le password aussi bien, on l'encrypte ou hash et ajoute le salt
    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) {
        return next(err);
      }
      //overwrite plain text password avec un encrypted password
      user.password = hash;
      // avance et enregistre ou save sauvegarde le model car tout est ok pour cela
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
  //candidatePassword est le password avec lequel un user essayer de sign in
  //ici this.password est une reference à notre user model, c'est notre hash et salt password
  //bcrypt en arrière plan fait la comparaison pour nous, il prend le salt plus le hash password et va en interne faire le process hashing
  // c'-à-d hasher ou crypter avec salt et le new password en prenant le candidatePassword et voir s'ils sont égaux ou correspondent oui ou non
  //s'ils sont égaux , isMatch va être vrai et s'ils ne correspondent pas isMatch va etre faux
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) {
      return callback(err);
    }
    callback(null, isMatch);
  });
};

//On save Hook, encrypt password

//model class pour tous les users
const ModelClass = mongoose.model('user', userSchema);

//export
module.exports = ModelClass;
