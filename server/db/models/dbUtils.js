'use strict';
var pg = require('pg');

var dbUtils = {};

//Need a check to verify that a connection is still alive
//KnexJS has a 'ping' function -- run a 'SELECT 1' query??? 

dbUtils.toClientDB = function (dbName) {
    var knex = require('knex')({
        client: 'pg',
        connection: 'postgres://localhost:5432/' + dbName,
        searchPath: 'knex,public'
    })
}

dbUtils.checkConnection = function (dbName){
    knex.select(1);
}

dbUtils.getAssociationTable = function (dbName, tableName){
    knex(dbName+"_assoc").where('Table1, tableName').orWhere('Table2', tableName);
}



module.exports = dbUtils;
