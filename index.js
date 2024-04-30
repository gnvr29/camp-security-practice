// index.js
//Importa a biblioteca bcrypt para comparar a senha fornecida com o hash da senha no banco de dados
const bcrypt = require('bcrypt');
const express = require('express');
const bodyParser = require('body-parser');
const User = require('./models/User');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

// Endpoint de login (vulnerável a SQL Injection)
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ where: {username} });

  if (user) {
    //Compara a senha fornecida com a senha criptografada do usuário
    const isPsswdValid = await bcrypt.compare(password, user.password);
    if(isPsswdValid){
      res.json({ message: 'Login successful', user });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// Endpoint de listagem de usuários (expondo dados sensíveis)
app.get('/users', async (req, res) => {
  //Dentre os atributos apresentados, estava a senha, o que poderia expor informacoes sigilosas
  const users = await User.findAll({ attributes: ['id', 'username'] });
  res.json(users);
});

// Endpoint de detalhe do usuário logado (expondo senha)
app.get('/profile', async (req, res) => {
  const { username } = req.query;
  const user = await User.findOne({ where: { username: username ?? null } });
  if (user) {
    //Ao inves de exibir todas as informacoes, exibe apenas as informacoes selecionadas
    res.json(user.username);
  } else {
    res.status(404).json({ message: 'User not found' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
