app.factory('TableFactory', function ($http, $stateParams) {

	var TableFactory = {};

	function resToData(res) {
        return res.data;
    }

    TableFactory.getAllTables = function(dbName){
    	return $http.get('/api/clientdb/' + dbName)
    	.then(resToData)
    }

    TableFactory.getSingleTable = function(dbName, tableName){
        return $http.get('/api/clientdb/' + dbName + '/' + tableName)
        .then(resToData)
    }

    TableFactory.getDbName = function(dbName){
        return $http.get('/api/masterdb/' + dbName)
        .then(resToData)
    }

    TableFactory.filter = function(dbName, tableName, data) {
        return $http.put('/api/clientdb/' + dbName + '/' + tableName + '/filter', data)
    }

    TableFactory.updateBackend = function(dbName, tableName, data) {
        return $http.put('api/clientdb/' + dbName + '/' + tableName, data)
        .then(resToData);
    }

    TableFactory.addRow = function(dbName, tableName, rowNumber) {
        return $http.post('api/clientdb/addrow/' + dbName + '/' + tableName, {rowNumber: rowNumber})
        .then(resToData);
    }

    TableFactory.removeRow = function(dbName, tableName, rowId){
        return $http.delete('/api/clientdb/' + dbName + '/' + tableName + '/' + rowId)
        .then(resToData)
    }

    TableFactory.removeColumn = function(dbName, tableName, columnName){
        return $http.delete('/api/clientdb/' + dbName + '/' + tableName + '/column/' + columnName)
        .then(resToData)
    }

    TableFactory.addColumn = function(dbName, tableName, numNewCol){
        return $http.post('api/clientdb/addcolumn/' + dbName + '/' + tableName + '/' + numNewCol)
    }
    TableFactory.createTable = function(table){
        table.dbName = $stateParams.dbName;
        return $http.post('/api/clientdb', table)
        .then(resToData);
    }

    TableFactory.deleteTable = function(currentTable) {
        console.log(currentTable);
        return $http.delete('/api/clientdb/' + currentTable.dbName + '/' + currentTable.tableName)
    }

    TableFactory.makeAssociations = function(association, dbName) {
        return $http.post('/api/clientdb/' + dbName + '/association', association)
        .then(resToData);
    }

    TableFactory.deleteDb = function(dbName) {
        return $http.delete('/api/clientdb/' + dbName)
        .then(resToData);
    }


	return TableFactory; 
})