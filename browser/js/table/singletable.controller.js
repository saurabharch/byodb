app.controller('SingleTableCtrl', function ($scope, singleTable, $stateParams, TableFactory, $state) {
	$scope.singleTable = singleTable;

	$scope.currentTable = $stateParams;

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


	//sends the filtering query and then goes to the filtered state
	$scope.filter = function(dbName, tableName, data) {
		TableFactory.filter(dbName, tableName, data)
		.then(function(result) {
			console.log(result);
			$state.go('Table.filtered', {dbName : $stateParams.dbName, tableName: $stateParams.tableName})
		})
	}

});
