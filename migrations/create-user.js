// migrations/create-user.js
const { DataTypes } = require('sequelize');
//Biblioteca utilizada para criptografar a senha
const bcrypt = require('bcrypt');
const sequelize = require('../sequelize');

module.exports = {
  up: async (queryInterface) => {
    await queryInterface.createTable('users', {
      id: {
        allowNull: false,
        autoIncrement: true,
        primaryKey: true,
        type: DataTypes.INTEGER,
      },
      username: {
        allowNull: false,
        type: DataTypes.STRING,
      },
      password: {
        allowNull: false,
        type: DataTypes.STRING,
      },
      createdAt: {
        allowNull: false,
        type: DataTypes.DATE,
      },
      updatedAt: {
        allowNull: false,
        type: DataTypes.DATE,
      },
    });
    //Tempo utilizado no processo de hashing
    const saltRounds = 10;
    //Senha criptografada
    const hashedPsswd = await bcrypt.hash(password, saltRounds);
    //Armazena a senha criptografada
    await queryInterface.bulkInsert('users', [{
      username: username,
      password: hashedPsswd,
    }], {});

  },
  down: async (queryInterface) => {
    await queryInterface.dropTable('users');
  },
};
