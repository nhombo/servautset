//partie qui inial de l'appli
const express = require('express');
const http = require('http');
const bodyParser = require('body-parser');
const morgan = require('morgan');

const route = require('./router');

const mongoose = require('mongoose');
mongoose.connect(
  'mongodb://localhost:27017/auth',
  { useNewUrlParser: true }
);

//setup pour App
const app = express();
app.use(morgan('combined'));
app.use(bodyParser.json({ type: '*/*' }));

route(app);
//partie setup server
const port = process.env.PORT || 3093;
app.listen(port);
const server = http.createServer(app);
console.log('le server écoute sur le port ', port);
