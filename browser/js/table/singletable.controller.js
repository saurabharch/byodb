app.controller('SingleTableCtrl', function($scope, TableFactory, $stateParams, singleTable, $window, $state, $uibModal, associations) {

    ///////////////////////////////Putting stuff on scope/////////////////////////////////////////////////

    $scope.theDbName = $stateParams.dbName;
    $scope.theTableName = $stateParams.tableName;
    $scope.singleTable = singleTable[0];
    $scope.selectedAll = false;
    $scope.associations = associations;



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
                TableFactory.removeRow(db, table, row[0])
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

    $scope.updateRow = function(old, newCell, row, i, j) {
        row[i] = newCell;
        var rowObj = {};
        var cols = $scope.originalColVals;
        for (var c = 0; c < cols.length; c++) {
            var colName = cols[j];
            if(row[c] !== undefined) rowObj[colName] = row[c];
            rowObj['id'] = i;
        }

        // if there is nothing in the array to update, push the update into it
        if ($scope.rowValsToUpdate.length === 0) $scope.rowValsToUpdate.push(rowObj);
        else {
            // check to see if the row is already scheduled to be updated, if it is, then update it with the new thing to be updated
            for (var e = 0; e < $scope.rowValsToUpdate.length; e++) {
                if ($scope.rowValsToUpdate[e].id === rowObj['id']) {
                    $scope.rowValsToUpdate[e] = rowObj;
                    return;
                }
            }
            $scope.rowValsToUpdate.push(rowObj);
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

    $scope.selectedColumns = {};

    $scope.getDataFromColumns = function(val) {

        var columnName = $scope.columnsForQuery[0]['columns'][val.i];
        var tableName = val.tableName

        if (!$scope.selectedColumns[tableName]) $scope.selectedColumns[tableName] = [];
        if ($scope.selectedColumns[tableName].indexOf(columnName) !== -1) {
            $scope.selectedColumns[tableName].splice($scope.selectedColumns[tableName].indexOf(columnName), 1)
        } else {
            $scope.selectedColumns[tableName].push(columnName);
        }
    }

    // Running the query + rendering the query
    $scope.resultOfQuery = [];

    $scope.queryResult;

    $scope.runJoin = function() {
        // dbName, table1, arrayOfTables, selectedColumns, associations
        TableFactory.runJoin($scope.theDbName, $scope.theTableName, $scope.tablesToQuery, $scope.selectedColumns, $scope.associations)
            .then(function(queryResult) {
                $scope.queryResult = queryResult;
            })
            .then(function() {
                $state.go('Table.Single.query');
            })
            .then(function() {
                $scope.CreateQueryColumns();
                $scope.CreateQueryRows()
            })
    }


    $scope.CreateQueryColumns = function() {
        $scope.columnsforQuery = [];
        // $scope.originalColVals = [];
        var table = $scope.queryResult[0];


        for (var prop in table) {
            if (prop !== 'created_at' && prop !== 'updated_at') {
                $scope.columnsforQuery.push(prop);
                // $scope.originalColVals.push(prop);
            }
        }
    }

    $scope.CreateQueryRows = function() {
        $scope.instanceQueryArray = [];
        $scope.queryResult.forEach(function(row) {
            var rowValues = [];
            var rowObj = {};

            for (var prop in row) {
                if (prop !== 'created_at' && prop !== 'updated_at') rowValues.push({
                    col: prop,
                    value: row[prop]
                })
            }
            rowObj.values = rowValues;
            $scope.instanceQueryArray.push(rowObj);
        })
    }

});
