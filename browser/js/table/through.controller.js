app.controller('ThroughCtrl', function($scope, TableFactory, $stateParams, associations, singleTable, $uibModal) {

    $scope.associations = associations;
    $scope.twoTables = [];
    $scope.singleTable = singleTable[0];
    $scope.theDbName = $stateParams.dbName;
    $scope.tableName = $stateParams.tableName;

    function get2Tables() {
        $scope.associations.forEach(function(assoc) {
            if (assoc['Through'] === $stateParams.tableName) {
                $scope.twoTables.push(assoc['Table1']);
                $scope.twoTables.push(assoc['Table2']); //here - come back
            }
        })
    }

    get2Tables();

    function CreateColumns() {
        $scope.columns = [];
        var table = singleTable[0][0];
        for (var prop in table) {
            $scope.columns.push(prop);
        }
    }

    CreateColumns();


    //this function will re run when the filter function is invoked, in order to repopulate the table
    function CreateRows() {

        $scope.instanceArray = [];
        $scope.singleTable.forEach(function(row) {
            var rowValues = [];
            for (var prop in row) {
                rowValues.push(row[prop])
            }
            $scope.instanceArray.push(rowValues)
        })
    }

    // Sort the values in singleTable so that all the values for a given row are grouped
    CreateRows();

    // $scope.animationsEnabled = true;

    $scope.open = function(dbName, tableName, index, row, columnName) {
        console.log(dbName, tableName, index, row, columnName);
        var theTable = $scope.twoTables[index-1];
        console.log('twoTables', $scope.twoTables);
        console.log('theTable', theTable);

        var modalInstance = $uibModal.open({
            animation: $scope.animationsEnabled,
            templateUrl: 'js/table/through.modal.html',
            controller: 'ThroughModalCtrl',
            resolve: {
                theTable: function(TableFactory) {
                    return TableFactory.getSingleTable(dbName, theTable);
                },
                tableName : function() { return theTable },
                rowId : function() { return row },
                columnName : function() { return columnName }
            }
        });

        modalInstance.result.then(function() {
            console.log("CLOSED")
            $scope.$evalAsync();
        });
    };

    $scope.toggleAnimation = function() {
        $scope.animationsEnabled = !$scope.animationsEnabled;
    };

    $scope.newRow = function(db, table) {
       TableFactory.increment(db, table)
       .then(function(result) {
        console.log(result);
        $scope.instanceArray = result;
         // CreateColumns();
         // CreateRows();
         $scope.$evalAsync();
       })
    }

})
