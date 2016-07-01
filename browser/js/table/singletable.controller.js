app.controller('SingleTableCtrl', function ($scope, TableFactory, $stateParams, singleTable, $window, $state, $uibModal, associations) {
	
	///////////////////////////////Putting stuff on scope/////////////////////////////////////////////////

	$scope.theDbName = $stateParams.dbName;
	$scope.theTableName = $stateParams.tableName;
	$scope.singleTable = singleTable[0];
	$scope.foreignIds = singleTable[1];
    $scope.selectedAll = false;
    $scope.associations = associations;

    if($scope.associations.length > 0){
    	if($scope.associations[0].Relationship1 === 'hasMany' && $scope.associations[0].Relationship2 === 'hasOne'){
    		if($scope.theTableName !== $scope.associations[0].Table2)
    		$scope.virtualColumn = $scope.associations[0].Alias1
    		$scope.virtualColumnTable = $scope.associations[0].Table2;
    		$scope.virtualColumnKey = $scope.associations[0].Alias2;
    	}else if($scope.associations[0].Relationship2 === 'hasMany' && $scope.associations[0].Relationship1 === 'hasOne'){
    		if($scope.theTableName !== $scope.associations[0].Table1)
    		$scope.virtualColumn = $scope.associations[0].Alias2
    		$scope.virtualColumnTable = $scope.associations[0].Table1;
    		$scope.virtualColumnKey = $scope.associations[0].Alias1;
    	}else if($scope.associations[0].Relationship1 === 'hasMany' && $scope.associations[0].Relationship2 === 'hasMany'){
    		if($scope.theTableName === $scope.associations[0].Table1){
    			$scope.virtualColumn = $scope.associations[0].Alias2
    			$scope.virtualColumnTable = $scope.associations[0].Through;
    			$scope.virtualColumnKey = $scope.associations[0].Alias2;	
    		}else if($scope.theTableName === $scope.associations[0].Table2)
	    		$scope.virtualColumn = $scope.associations[0].Alias1
	    		$scope.virtualColumnTable = $scope.associations[0].Through;
	    		$scope.virtualColumnKey = $scope.associations[0].Alias1;
    	}
    }

    // $scope.getPrimaryKeys = function(id, dbName, table, key){
    // 	TableFactory.getPrimaryKeys(id, dbName, table, key)
    // 	.then(function(result){
    // 		$state.go("Table.Join", {rowId: id, dbName: dbName, table: table, key: key});
    // 	})
    // }

	$scope.currentTable = $stateParams;

	$scope.myIndex = 1;

	$scope.ids = $scope.singleTable.map(function(row){
		return row.id;
	})

	//delete a row 
	$scope.showDelete = false;
	$scope.toggleDelete = function(){
		$scope.showDelete = !$scope.showDelete
	}

    $scope.deleteSelected = function(db, table, instanceArray){
        instanceArray.forEach(function(row){
            if(row.selected){
                TableFactory.removeRow(db, table, row[0])
                .then(function(result){
                    $scope.singleTable = result;
                    CreateRows();
                })
            }
        })
        $scope.showDelete = false;
    }

    $scope.selectAll = function(instanceArray){
        if($scope.selectedAll){
            instanceArray.forEach(function(row){
                row.selected = true;
            })
        }
        else{
            instanceArray.forEach(function(row){
                row.selected = false;
            })
        }
    }

    $scope.uncheckSelectAll = function(instanceArray){
        if($scope.selectedAll===true){
            $scope.selectedAll = false;
        }
    }

	$scope.removeRow = function(db, table, row){
		TableFactory.removeRow(db, table, row)
		.then(function(result){
			$scope.singleTable = result;
			CreateRows();
		})
	}

	$scope.removeColumn = function(db, table, columnName){
		TableFactory.removeColumn(db, table, columnName)
		.then(function(result){
			$scope.singleTable = result;
			CreateRows();
			CreateColumns();
		})
	}

	$scope.newRow = function(db, table, arr){
		var allIds = [];
		arr.forEach(function(rowData){
			allIds.push(rowData[0])
		})
		var sorted = allIds.sort(function(a, b){return b - a})
		if(sorted.length > 0){
			TableFactory.addRow(db, table, sorted[0] + 1)
			.then(function(result){
				$scope.singleTable = result;
				CreateRows();
			})

		} else{
			TableFactory.addRow(db, table, 1)
			.then(function(result){
				$scope.singleTable = result;
				CreateRows();
			})
		}
	}

	$scope.addColumn = function(db, table){
		var colNums = $scope.columns.join(' ').match(/\d+/g);
		if(colNums){
			var sortedNums = colNums.sort(function(a, b){return b - a})
			var numInNew = Number(sortedNums[0]) + 1;
			var nameNewCol = 'Column ' + numInNew.toString();

			TableFactory.addColumn(db, table, nameNewCol)
			.then(function(){
				return TableFactory.getSingleTable($stateParams.dbName, $stateParams.tableName)
			})
			.then(function(theTable){
				$scope.singleTable = theTable[0];
				CreateColumns();
				CreateRows();
			})
		} else {
			var nextColNum = $scope.columns.length + 1;
			var newColName = 'Column ' + nextColNum;
			TableFactory.addColumn(db, table, 'Column 1')
			.then(function(){
				return TableFactory.getSingleTable($stateParams.dbName, $stateParams.tableName)
			})
			.then(function(theTable){
				$scope.singleTable = theTable[0];
				CreateColumns();
				CreateRows();
			})
		}
		
	}
	
	///////////////////////////////Organizing stuff into arrays/////////////////////////////////////////////////

	// Get all of the columns to create the columns on the bootstrap table
	

	function CreateColumns(){
		$scope.columns = [];
		$scope.originalColVals = [];
		var table = $scope.singleTable[0];


		for(var prop in table){
			if(prop !== 'created_at' && prop !== 'updated_at'){
				$scope.columns.push(prop);	
				$scope.originalColVals.push(prop);
			} 
		}
	}

	CreateColumns();

    //this function will re run when the filter function is invoked, in order to repopulate the table
    function CreateRows() {
    	var alias;
    	if($scope.associations.length > 0){
	        if($scope.associations[0].Relationship1 === 'hasOne'){
	        	alias = $scope.associations[0].Alias1;
	        }else if($scope.associations[0].Relationship2 === 'hasOne'){
	        	alias = $scope.associations[0].Alias2;
	        }	
    	}
        $scope.instanceArray = [];
        $scope.singleTable.forEach(function(row) {
            var rowValues = [];
            for (var prop in row) {
            	if ($scope.associations.length>0 && prop === alias && row[prop] === null) {
            		row[prop] = []
            		$scope.foreignIds.forEach(function(id){
            			row[prop].push(id.id)
            		})
            		// rowValues.push(row[prop])
            	}
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
                $scope.singleTable = result.data;
                CreateRows();
            })
    }


	//************ Important *********
		// Make sure to update the row values BEFORE the column name
			// The rowValsToUpdate array stores the values of the ORIGINAL column names so if the column name is updated after the row value, we still have reference to which column the row value references


	///////////////////////////////Updating Column Stuff/////////////////////////////////////////////////

	$scope.colValsToUpdate = [];

	$scope.updateColumns = function(old, newColName, i){
		$scope.columns[i] = newColName;

		var colObj= {oldVal: $scope.originalColVals[i], newVal: newColName};

		// if there is nothing in the array to update, push the update into it
		if($scope.colValsToUpdate.length === 0){ $scope.colValsToUpdate.push(colObj); }
		else {
			for(var e = 0; e < $scope.colValsToUpdate.length; e++){
				if($scope.colValsToUpdate[e].oldVal === colObj.oldVal){
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

	$scope.updateRow = function(old, newCell, row, i){
		row[i] = newCell;
		var rowObj = {};
		var cols = $scope.originalColVals;
		for(var c = 0; c < cols.length; c++){
			var colName = cols[c];
			rowObj[colName] = row[c];
		}

		// if there is nothing in the array to update, push the update into it
		if($scope.rowValsToUpdate.length === 0) $scope.rowValsToUpdate.push(rowObj);
		else {
			// check to see if the row is already scheduled to be updated, if it is, then update it with the new thing to be updated
			for(var e = 0; e < $scope.rowValsToUpdate.length; e++){
				if($scope.rowValsToUpdate[e].id === rowObj.id){ 
					$scope.rowValsToUpdate[e] = rowObj;
					return;
				}
			}
			$scope.rowValsToUpdate.push(rowObj);
		}
	}

	$scope.updateBackend= function() {
		var data = {rows : $scope.rowValsToUpdate, columns : $scope.colValsToUpdate}
		TableFactory.updateBackend($scope.theDbName, $scope.theTableName, data);
	}


	$scope.deleteTable = function() {
		TableFactory.deleteTable($scope.currentTable)
		.then(function() {
			$state.go('Table', {dbName : $scope.theDbName}, {reload : true})
		})
	}

});