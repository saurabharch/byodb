app.controller('JoinTableCtrl', function ($scope, TableFactory, $stateParams, joinTable) {
	

	console.log(joinTable)
	// TableFactory.getPrimaryKeys

	// function CreateColumns(){
	// 	$scope.columns = [];
	// 	var table = $scope.singleTable[0];


	// 	for(var prop in table){
	// 		if(prop !== 'created_at' && prop !== 'updated_at'){
	// 			$scope.columns.push(prop);	
	// 			$scope.originalColVals.push(prop);
	// 		} 
	// 	}
	// }

	// CreateColumns();

 //    //this function will re run when the filter function is invoked, in order to repopulate the table
 //    function CreateRows() {
 //    	var alias;
 //    	if($scope.associations.length > 0){
	//         if($scope.associations[0].Relationship1 === 'hasOne'){
	//         	alias = $scope.associations[0].Alias1;
	//         }else if($scope.associations[0].Relationship2 === 'hasOne'){
	//         	alias = $scope.associations[0].Alias2;
	//         }	
 //    	}
 //        $scope.instanceArray = [];
 //        $scope.singleTable.forEach(function(row) {
 //            var rowValues = [];
 //            for (var prop in row) {
 //            	if ($scope.associations.length>0 && prop === alias && row[prop] === null) {
 //            		row[prop] = []
 //            		$scope.foreignIds.forEach(function(id){
 //            			row[prop].push(id.id)
 //            		})
 //            		// rowValues.push(row[prop])
 //            	}
 //                if (prop !== 'created_at' && prop !== 'updated_at') rowValues.push(row[prop])
 //            }
 //            $scope.instanceArray.push(rowValues)
 //        })
 //    }

 //    // Sort the values in singleTable so that all the values for a given row are grouped
 //    CreateRows();

})