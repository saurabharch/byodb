app.config(function ($stateProvider) {
    $stateProvider.state('Table', {
        url: '/:dbName',
        templateUrl: 'js/table/table.html',
        controller: 'TableCtrl',
        resolve: {
        	allTables: function(TableFactory, $stateParams){
                return TableFactory.getAllTables($stateParams.dbName);
        	}
        }
    });

    $stateProvider.state('Table.Single', {
        url: '/:tableName',
        templateUrl: 'js/table/singletable.html',
        controller: 'SingleTableCtrl',
        resolve: {
            singleTable: function(TableFactory, $stateParams){
                return TableFactory.getSingleTable($stateParams.dbName, $stateParams.tableName);
            },
            theDb: function(TableFactory, $stateParams){
                return TableFactory.getDbName($stateParams.dbName);
            },
        }
    });    

});