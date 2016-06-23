'use strict';

var db = require('../../db');
var Database = db.model('database');
var router = require('express').Router();
// var pg = require('knex')({
//   client: 'pg',
//   connection: process.env.PG_CONNECTION_STRING,
//   searchPath: 'knex,public'
// });
var pg = require('pg');
var Sequelize = require('sequelize');


module.exports = router;


router.post('/', function(req, res, next) {
    Database.create(req.body)
    .then(function(createdDB) {
        var dbName = createdDB.dbName;
        var connectionString = 'postgres://localhost:5432/masterDB';

        var client = new pg.Client(connectionString);
        client.connect();
        var query = client.query('CREATE DATABASE ' + dbName);
        query.on('end', function() { client.end(); });
    })
    .then(function() {
        res.sendStatus(201);
    })
    .catch(next);
})

