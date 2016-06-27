app.controller('SingleTableCtrl', function ($scope, singleTable) {
	$scope.singleTable = singleTable;

	// Get all of the columns to create the columns on the bootstrap table
	$scope.columns = [];
	$scope.originalColVals = [];

	var table = singleTable[0];

	for(var prop in table){
		if(prop !== 'created_at' && prop !== 'updated_at') $scope.columns.push(prop);
		if(prop !== 'created_at' && prop !== 'updated_at') $scope.originalColVals.push(prop)
	}

	// Sort the values in sigleTable so that all the values for a given row are grouped
	$scope.instanceArray = [];

	singleTable.forEach(function(row){
		var rowValues = [];
		for(var prop in row){
			if(prop !== 'created_at' && prop !== 'updated_at') rowValues.push(row[prop])
		}
		$scope.instanceArray.push(rowValues)
	})


	//************ Important *********
		// Make sure to update the row values BEFORE the column name
			// The rowValsToUpdate array stores the values of the ORIGINAL column names so if the column name is updated after the row value, we still have reference to which column the row value references


	///////////////////////////////Updating Column Stuff/////////////////////////////////////////////////

	$scope.colValsToUpdate = [];

	$scope.updateColumns = function(old, newColName, i){
		$scope.columns[i] = newColName;

		var colObj= {oldVal: $scope.originalColVals[i], newVal: newColName};

		// if there is nothing in the array to update, push the update into it
		if($scope.colValsToUpdate.length === 0) $scope.colValsToUpdate.push(colObj);
				
		// check to see if the row is already scheduled to be updated, if it is, then update it with the new thing to be updated
		for(var e = 0; e < $scope.colValsToUpdate.length; e++){
			if($scope.colValsToUpdate[e].old === colObj.old) $scope.colValsToUpdate = colObj;
			else $scope.colValsToUpdate.push(colObj);
		}
	}

	///////////////////////////////Updating Row Stuff/////////////////////////////////////////////////
	
	$scope.rowValsToUpdate = [];

	$scope.updateRow = function(old, val, row, i){
		row[i] = val;
		var rowObj = {};
		var cols = $scope.originalColVals;
		for(var c = 0; c < cols.length; c++){
			var colName = cols[c];
			rowObj[colName] = row[c];
		}

		// if there is nothing in the array to update, push the update into it
		if($scope.rowValsToUpdate.length === 0) $scope.rowValsToUpdate.push(rowObj);

		// check to see if the row is already scheduled to be updated, if it is, then update it with the new thing to be updated
		for(var e = 0; e < $scope.rowValsToUpdate.length; e++){
			if($scope.rowValsToUpdate[e].id === rowObj.id) $scope.rowValsToUpdate[e] = rowObj;
			else $scope.rowValsToUpdate.push(rowObj);
		}
	}

	$scope.logData=function () {
		console.log($scope.rowValsToUpdate)
		console.log($scope.colValsToUpdate)
        // if(employee !== undefined) $scope.editEmployee.push(employee);
        // console.log($scope.editEmployee);
     }

});
