app.controller('SingleTableCtrl', function($scope, TableFactory, $stateParams, singleTable, $window, $state, $uibModal, associations, $log) {

    ///////////////////////////////Putting stuff on scope/////////////////////////////////////////////////

    $scope.theDbName = $stateParams.dbName;
    $scope.theTableName = $stateParams.tableName;
    $scope.singleTable = singleTable[0].sort(function(a, b){
        if(a.id > b.id) return 1;
        if(a.id < b.id) return -1;
        return 0;
    });
    $scope.selectedAll = false;
    $scope.associations = associations;


    if($scope.associations.length>0) {
        if($scope.associations[0]['Through'] === $stateParams.tableName) {
            $state.go('Table.Through', {dbName : $stateParams.dbName, tableName : $stateParams.tableName})
        }
    }


    function foreignColumnObj() {
        var foreignCols = {};
        $scope.associations.forEach(function(row) {
            if (row.Table1 === $scope.theTableName && row.Relationship1 === 'hasOne') {
                foreignCols[row.Alias1] = row.Table2
            } else if (row.Table2 === $scope.theTableName && row.Relationship2 === 'hasOne') {
                foreignCols[row.Alias2] = row.Table1
            }
        })
        $scope.foreignCols = foreignCols;
    }

    foreignColumnObj();


    $scope.currentTable = $stateParams;

    $scope.myIndex = 1;

    $scope.ids = $scope.singleTable.map(function(row) {
        return row.id;
    })

    //delete a row 
    $scope.showDelete = false;
    $scope.toggleDelete = function() {
        $scope.showDelete = !$scope.showDelete
    }

    $scope.deleteSelected = function(db, table, instanceArray) {
        instanceArray.forEach(function(row) {
            if (row.selected) {
                TableFactory.removeRow(db, table, row['values'][0]['value'])
                    .then(function(result) {
                        $scope.singleTable = result;
                        CreateRows();
                    })
            }
        })
        $scope.showDelete = false;
    }

    $scope.selectAll = function(instanceArray) {
        if ($scope.selectedAll) {
            instanceArray.forEach(function(row) {
                row.selected = true;
            })
        } else {
            instanceArray.forEach(function(row) {
                row.selected = false;
            })
        }
    }

    $scope.uncheckSelectAll = function(instanceArray) {
        if ($scope.selectedAll === true) {
            $scope.selectedAll = false;
        }
    }

    $scope.removeRow = function(db, table, row) {
        TableFactory.removeRow(db, table, row)
            .then(function(result) {
                $scope.singleTable = result;
                CreateRows();
            })
    }

    $scope.removeColumn = function(db, table, columnName) {
        TableFactory.removeColumn(db, table, columnName)
            .then(function(result) {
                $scope.singleTable = result;
                CreateRows();
                CreateColumns();
            })
    }

    $scope.newRow = function(db, table, arr) {
        var allIds = [];
        arr.forEach(function(rowData) {
            allIds.push(rowData.values[0].value)
        })
        var sorted = allIds.sort(function(a, b) {
            return b - a
        })
        if (sorted.length > 0) {
            TableFactory.addRow(db, table, sorted[0] + 1)
                .then(function(result) {
                    $scope.singleTable = result;
                    CreateRows();
                })

        } else {
            TableFactory.addRow(db, table, 1)
                .then(function(result) {
                    $scope.singleTable = result;
                    CreateRows();
                })
        }
    }

    $scope.addColumn = function(db, table) {
        var colNums = $scope.columns.join(' ').match(/\d+/g);
        if (colNums) {
            var sortedNums = colNums.sort(function(a, b) {
                return b - a
            })
            var numInNew = Number(sortedNums[0]) + 1;
            var nameNewCol = 'Column ' + numInNew.toString();

            TableFactory.addColumn(db, table, nameNewCol)
                .then(function() {
                    return TableFactory.getSingleTable($stateParams.dbName, $stateParams.tableName)
                })
                .then(function(theTable) {
                    $scope.singleTable = theTable[0];
                    CreateColumns();
                    CreateRows();
                })
        } else {
            var nextColNum = $scope.columns.length + 1;
            var newColName = 'Column ' + nextColNum;
            TableFactory.addColumn(db, table, 'Column 1')
                .then(function() {
                    return TableFactory.getSingleTable($stateParams.dbName, $stateParams.tableName)
                })
                .then(function(theTable) {
                    $scope.singleTable = theTable[0];
                    CreateColumns();
                    CreateRows();
                })
        }

    }

    ///////////////////////////////Organizing stuff into arrays/////////////////////////////////////////////////

    // Get all of the columns to create the columns on the bootstrap table

    function CreateColumns() {
        $scope.columns = [];
        $scope.originalColVals = [];
        var table = $scope.singleTable[0];


        for (var prop in table) {
            if (prop !== 'created_at' && prop !== 'updated_at') {
                $scope.columns.push(prop);
                $scope.originalColVals.push(prop);
            }
        }
    }

    CreateColumns();

    function createVirtualColumns() {
        if ($scope.associations.length > 0) {
            $scope.virtualColumns = [];
            $scope.associations.forEach(function(row) {
                if (row.Table1 === $scope.theTableName && row.Relationship1 === 'hasMany') {
                    var virtual = {};
                    virtual.name = row.Alias1;
                    if (row.Through) {
                        virtual.table = row.Through;
                        virtual.columnkey = row.Alias1;
                    } else {
                        virtual.table = row.Table2;
                        virtual.columnkey = row.Alias2;
                    }
                    $scope.virtualColumns.push(virtual);
                } else if (row.Table2 === $scope.theTableName && row.Relationship2 === 'hasMany') {
                    var virtual = {};
                    virtual.name = row.Alias2;
                    if (row.Through) {
                        virtual.table = row.Through;
                        virtual.columnkey = row.Alias2;
                    } else {
                        virtual.table = row.Table1;
                        virtual.columnkey = row.Alias1;
                    }
                    $scope.virtualColumns.push(virtual);
                }
            })
        }
    }

    createVirtualColumns();

    //this function will re run when the filter function is invoked, in order to repopulate the table
    function CreateRows() {
        $scope.instanceArray = [];
        $scope.singleTable.forEach(function(row) {
            var rowValues = [];
            var rowObj = {};

            for (var prop in row) {
                if (prop !== 'created_at' && prop !== 'updated_at') rowValues.push({
                    col: prop,
                    value: row[prop]
                })
            }
            rowObj.values = rowValues;
            $scope.instanceArray.push(rowObj);
        })
    }

    // Sort the values in singleTable so that all the values for a given row are grouped
    CreateRows();
    //sends the filtering query and then re renders the table with filtered data
    $scope.filter = function(dbName, tableName, data) {
        TableFactory.filter(dbName, tableName, data)
            .then(function(result) {
                $scope.singleTable = result.data;
                CreateRows();
            })
    }


    $scope.checkForeign = function(col) {
        return $scope.foreignCols.hasOwnProperty(col);
    }

    $scope.findPrimary = TableFactory.findPrimary;

    //************ Important *********
    // Make sure to update the row values BEFORE the column name
    // The rowValsToUpdate array stores the values of the ORIGINAL column names so if the column name is updated after the row value, we still have reference to which column the row value references


    ///////////////////////////////Updating Column Stuff/////////////////////////////////////////////////

    $scope.colValsToUpdate = [];

    $scope.updateColumns = function(old, newColName, i) {
        $scope.columns[i] = newColName;

        var colObj = { oldVal: $scope.originalColVals[i], newVal: newColName };

        // if there is nothing in the array to update, push the update into it
        if ($scope.colValsToUpdate.length === 0) { $scope.colValsToUpdate.push(colObj); } else {
            for (var e = 0; e < $scope.colValsToUpdate.length; e++) {
                if ($scope.colValsToUpdate[e].oldVal === colObj.oldVal) {
                    $scope.colValsToUpdate[e] = colObj;
                    return;
                }
            }
            $scope.colValsToUpdate.push(colObj);
        }
        // check to see if the row is already scheduled to be updated, if it is, then update it with the new thing to be updated
    }

    ///////////////////////////////Updating Row Stuff/////////////////////////////////////////////////

    $scope.rowValsToUpdate = [];

    $scope.updateRow = function(old, newCell, row, i, j){
        var cols = $scope.originalColVals;
        var found = false;
        var colName = cols[j];
        for(var k = 0; k < $scope.rowValsToUpdate.length; k++){
            var obj = $scope.rowValsToUpdate[k];
            console.log(obj)
            if(obj['id'] === i){
                found = true;
                if(obj[colName]) obj[colName] = newCell;
                obj[colName] = newCell;
            }
        }
        if(!found) {
            var rowObj = {};
            rowObj['id'] = i;
            rowObj[colName] = newCell;
            $scope.rowValsToUpdate.push(rowObj)
        }
    }

    $scope.updateBackend = function() {
        var data = { rows: $scope.rowValsToUpdate, columns: $scope.colValsToUpdate }
        TableFactory.updateBackend($scope.theDbName, $scope.theTableName, data);
    }


    $scope.deleteTable = function() {
        TableFactory.deleteTable($scope.currentTable)
            .then(function() {
                $state.go('Table', { dbName: $scope.theDbName }, { reload: true })
            })
    }

    ///////////////////////////////Querying Stuff/////////////////////////////////////////////////

    $scope.currentTableAssociations = [];

    $scope.tablesToQuery = [];

    associations.forEach(function(row) {
        if (row.Table1 === $scope.theTableName && $scope.currentTableAssociations.indexOf(row.Table2) == -1) {
            $scope.currentTableAssociations.push(row.Table2);
        } else if (row.Table2 === $scope.theTableName && $scope.currentTableAssociations.indexOf(row.Table1) == -1) {
            $scope.currentTableAssociations.push(row.Table1);
        }
    })

    $scope.getAssociated = function(val) {
        if ($scope.tablesToQuery.indexOf($scope.currentTableAssociations[val]) === -1) {
            $scope.tablesToQuery.push($scope.currentTableAssociations[val])
        } else {
            var i = $scope.tablesToQuery.indexOf($scope.currentTableAssociations[val]);
            $scope.tablesToQuery.splice(i, 1)
        }
    }

    $scope.columnsForQuery = [];

    $scope.getColumnsForTable = function() {
        var promisesForColumns = [];
        $scope.tablesToQuery.forEach(function(tableName) {
            return promisesForColumns.push(TableFactory.getColumnsForTable($scope.theDbName, tableName))
        })
        Promise.all(promisesForColumns)
            .then(function(columns) {
                columns.forEach(function(column) {
                    $scope.columnsForQuery.push(column);
                    $scope.$evalAsync()
                })
            })

    }

    var selectedColumns = {};
    var queryTable;

    $scope.getDataFromColumns = function(val) {
        if(!selectedColumns) selectedColumns = [];

        var columnName = $scope.columnsForQuery[0]['columns'][val.i];
        var tableName = val.tableName
        queryTable = tableName;

        if (!selectedColumns[tableName]) selectedColumns[tableName] = [];
        if (selectedColumns[tableName].indexOf(columnName) !== -1) {
            selectedColumns[tableName].splice(selectedColumns[tableName].indexOf(columnName), 1)
        } else {
            selectedColumns[tableName].push(columnName);
        }
        $scope.selectedColumns = selectedColumns;
    }


    // Running the query + rendering the query
    $scope.resultOfQuery = [];

    $scope.queryResult;

    $scope.arr = [];


    // theTableName

    $scope.runJoin = function() {
        // dbName, table1, arrayOfTables, selectedColumns, associations
        var columnsToReturn = $scope.columns.map(function(colName){
            return $scope.theTableName + '.' + colName;
        })
        for(var prop in $scope.selectedColumns){
           $scope.selectedColumns[prop].forEach(function(col){
                columnsToReturn.push(prop + '.' + col)
           })
        }
        TableFactory.runJoin($scope.theDbName, $scope.theTableName, $scope.tablesToQuery, $scope.selectedColumns, $scope.associations, columnsToReturn)
            .then(function(queryResult) {
                console.log('QUERYRRESULT', queryResult);
                $scope.queryResult = queryResult;
            })
            .then(function() {
                $state.go('Table.Single.query');
            })
    }

    $scope.animationsEnabled = true;

    $scope.open = function (dbName, tblName, col, index) {

      var modalInstance = $uibModal.open({
        animation: $scope.animationsEnabled,
        backdrop: false,
        templateUrl: 'js/table/association.modal.html',
        controller: 'AssociationInstanceCtrl',
        resolve: {
          foreignCols: function () {
            return $scope.foreignCols;
          },
          forTable: function(TableFactory){
            console.log(tblName)
            return TableFactory.findPrimary(dbName, tblName);
          },
          forTableName: function(){
            return tblName;
          },
          currTable: function(){
            return $scope.theTableName
          },
          colName: function (){
            return col;
          },
          id1: function(){
            return index;
          }
        }
      });

      modalInstance.result.then(function () {
        console.log("CLOSED")
        $scope.$evalAsync();
      });
    };

    $scope.toggleAnimation = function () {
      $scope.animationsEnabled = !$scope.animationsEnabled;
    };

    $scope.filteredRows=[];
    $scope.currentPage=1;
    $scope.numPerPage=10;
    $scope.maxSize=5;

    $scope.$watch("currentPage + numPerPage", function(){
        var begin = (($scope.currentPage - 1) * $scope.numPerPage);
        var end = begin + $scope.numPerPage;
        $scope.filteredRows = $scope.instanceArray.slice(begin, end);
    })

});
