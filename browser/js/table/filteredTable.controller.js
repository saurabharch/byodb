app.controller('FilteredTableCtrl', function ($scope, singleTable, $stateParams, TableFactory, filteredTable) {
	
	$scope.filteredTable = filteredTable;

	// Get all of the column to create the column on the bootstrap table
	$scope.column = [];

	var table = filteredTable[0];

	for(var prop in table){
		if(prop !== 'created_at' && prop !== 'updated_at') $scope.column.push(prop)
	}

	// Sort the values in filteredTable so that all the values for a given row are grouped
	$scope.instanceArray = [];

	filteredTable.forEach(function(row){
		var rowValues = [];
		for(var prop in row){
			if(prop !== 'created_at' && prop !== 'updated_at') rowValues.push(row[prop])
		}
		$scope.instanceArray.push(rowValues)
	})
	
});
