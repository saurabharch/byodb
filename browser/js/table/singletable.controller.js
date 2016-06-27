app.controller('SingleTableCtrl', function ($scope, singleTable) {
	$scope.singleTable = singleTable;

	// Get all of the columns to create the columns on the bootstrap table
	$scope.columns = [];

	var table = singleTable[0];

	for(var prop in table){
		if(prop !== 'created_at' && prop !== 'updated_at') $scope.columns.push(prop)
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

	
	$scope.valsToUpdate = [];

	$scope.update = function(old, val, row, i){
		row[i] = val;
		var rowObj = {};
		var cols = $scope.columns;
		for(var c = 0; c < cols.length; c++){
			var colName = cols[c];
			rowObj[colName] = row[c];
		}

		console.log(val)

		// if there is nothing in the array to update, push the update into it
		if($scope.valsToUpdate.length === 0) $scope.valsToUpdate.push(rowObj);

		// check to see if the row is already scheduled to be updated, if it is, then update it with the new thing to be updated
		for(var e = 0; e < $scope.valsToUpdate.length; e++){
			if($scope.valsToUpdate[e].id === rowObj.id) $scope.valsToUpdate[e] = rowObj;
			else $scope.valsToUpdate.push(rowObj);
		}

	}

	$scope.logData=function () {
		console.log($scope.valsToUpdate)
        // if(employee !== undefined) $scope.editEmployee.push(employee);
        // console.log($scope.editEmployee);
     }

});
