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
            }
        }
    }); 

    $stateProvider.state('Table.filtered', {
        url: '/:tableName/filtered',
        templateUrl: 'js/table/filteredTable.html',
        controller: 'FilteredTableCtrl',
        params : {
            result : null
        },
        resolve: {
            filteredTable: function(TableFactory, $stateParams){
                return TableFactory.filter($stateParams.dbName, $stateParams.tableName, result);
            }
        }
    });      

});