#include "HibeRotate.h"
#include <vector>

//#include "HibeDerive.h"

int delete_node(HIBENode *node) {
	//TODO: Delete hibe data from TPM
	//if (node->left != NULL || node->right != NULL)
	//	return -1;
	delete node;
	return 0;
}

// Assuming that the initial epoch is 0
HIBETree *new_hibe_tree(void *hibe_data, std::vector<int> &identities, int max_depth) {
	HIBETree *tree = new HIBETree;
	HIBENode *root = new HIBENode;

	root->is_deleted = false;
	root->is_root = true;
	root->depth = 0;
	root->epoch_number = 0;
	root->hibe_data = hibe_data;
	root->parent = NULL;
	root->left = NULL;
	root->right = NULL;

	tree->root = root;
	tree->current_node = root;
	tree->max_depth = max_depth;
	tree->current_epoch = 0;
	tree->identifiers = identities;

	return tree;
}

unsigned long long int size_of_subtree(HIBENode *node, HIBETree *tree) { 
	if (node == NULL || tree == NULL)
		return 0;
	int d = tree->max_depth - node->depth;
	if (d < 0)
		return 0;

	unsigned long long int sz = 1;
	while (d) {
		sz = sz * 2;
		d--;
	}

	return 1 + sz;
}

HIBENode *parent_to_next_epoch_node(HIBENode *root, int current_epoch, HIBETree *tree) {
	if (root == NULL)
		return NULL;

	if (current_epoch == 1)
		return root;

	int size_left = size_of_subtree(root->left, tree);
	if (current_epoch > 1 + size_left)
		return parent_to_next_epoch_node(root->right, current_epoch - 1 - size_left, tree);
	if (current_epoch == 1 + size_left)
		return root;
	return parent_to_next_epoch_node(root->left, current_epoch - 1, tree);
}


// Allocates and derives the key for the new node
// Deletes all the other nodes
int compute_next_epoch(HIBETree *tree) {
	if (tree == NULL)
		return -1;

	HIBENode *parent = parent_to_next_epoch_node(tree->root, tree->current_epoch + 1, tree);
	HIBENode *n = new HIBENode;
	if (!n)
		return -2;

	n->left = NULL;
	n->right = NULL;
	n->is_deleted = false; 
	n->is_root = false;
	n->depth = parent->depth + 1;
	n->epoch_number = tree->current_epoch + 1;
	n->parent = parent;

	if (parent->left == NULL) {
		//TODO: Implement this
		n->hibe_data = NULL;//derive_epoch_hibe(tree, parent, 1);
		parent->left = n;
	} else if (parent->right == NULL) {
		//TODO: Implement this
		n->hibe_data = NULL; // derive_epoch_hibe(tree, parent, 0);
		parent->right = n;
		// TODO: Work on the deletion and the TPM stuff
		int ret = delete_node(tree->current_node);
		if (ret != 0)
			return -4;

		ret = delete_node(parent);
		if (ret != 0)
			return -5;
	} else {
		return -3;
	}


	tree->current_epoch++;
	tree->current_node = n;
	
	return 0;
}
