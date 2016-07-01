app.controller('JoinTableCtrl', function ($scope, TableFactory, $stateParams, joinTable) {

	function CreateColumns(){
		$scope.columns = [];
		var table = joinTable;


		for(var prop in table){
			if(prop !== 'created_at' && prop !== 'updated_at'){
				$scope.columns.push(prop);	
			} 
		}
	}

	CreateColumns();

    //this function will re run when the filter function is invoked, in order to repopulate the table
    function CreateRows() {
    	var alias;
        $scope.instanceArray = [];
        joinTable.forEach(function(row) {
            var rowValues = [];
            for (var prop in row) {
                if (prop !== 'created_at' && prop !== 'updated_at') rowValues.push(row[prop])
            }
            $scope.instanceArray.push(rowValues)
        })
    }

    // Sort the values in singleTable so that all the values for a given row are grouped
    CreateRows();

})