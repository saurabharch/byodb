app.controller('SingleTableCtrl', function($scope, singleTable, $stateParams, TableFactory, $state) {
    $scope.singleTable = singleTable;

    $scope.currentTable = $stateParams;

    // Get all of the columns to create the columns on the bootstrap table
    $scope.columns = [];

    var table = singleTable[0];

    for (var prop in table) {
        if (prop !== 'created_at' && prop !== 'updated_at') $scope.columns.push(prop)
    }

    //this function will re run when the filter function is invoked, in order to repopulate the table
    function CreateRows() {
        $scope.instanceArray = [];
        $scope.singleTable.forEach(function(row) {
            var rowValues = [];
            for (var prop in row) {
                if (prop !== 'created_at' && prop !== 'updated_at') rowValues.push(row[prop])
            }
            $scope.instanceArray.push(rowValues)
        })
    }

    // Sort the values in singleTable so that all the values for a given row are grouped
    CreateRows();

    //sends the filtering query and then re renders the table with filtered data
    $scope.filter = function(dbName, tableName, data) {
        TableFactory.filter(dbName, tableName, data)
            .then(function(result) {
                console.log(result);
                $scope.singleTable = result.data;
                CreateRows();
            })
    }

});
