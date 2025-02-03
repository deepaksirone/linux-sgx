#include "HibeRotate.h"
#include <vector>

//#include "HibeDerive.h"

extern "C" char *derive_private_key_rotation(
    int32_t total_depth,
    int32_t depth_of_pvt_key,
    char *private_key,
    char *setup_params,
    int32_t *out_size,
    int32_t *capacity
);

extern "C" int deallocate_rust_vector(
    char *ptr,
    int32_t length,
    int32_t capacity
);

int delete_node(HIBENode *node) {
	//TODO: Delete hibe data from TPM
	//if (node->left != NULL || node->right != NULL)
	//	return -1;
	if (!node)
		return -1;

	hibe_data_t *hibe_data = (hibe_data_t *)node->hibe_data;
	if (hibe_data->is_rust_vector) {
		deallocate_rust_vector(hibe_data->private_key, hibe_data->vector_size, hibe_data->vector_capacity);
	}

	delete node;
	return 0;
}

hibe_data_t *derive_epoch_hibe(HIBETree *tree, HIBENode *parent, int next_id) {
	if (!tree || !parent)
		return NULL;
	hibe_data_t *hibe_data = (hibe_data_t *)parent->hibe_data;
	char *parent_pvt_key = hibe_data->private_key;

	int32_t vector_size;
	int32_t vector_capacity;

	//return NULL;
	char *new_epoch_pvt_key = derive_private_key_rotation(
			tree->hibe_depth + tree->max_depth,
			tree->hibe_depth + parent->depth,
			parent_pvt_key, hibe_data->setup_keys,
			&vector_size, &vector_capacity);

	//return NULL;
	if (!new_epoch_pvt_key)
		return NULL;

	hibe_data_t *new_hibe_data = (hibe_data_t *)malloc(sizeof(hibe_data_t));
	new_hibe_data->depth = hibe_data->depth;
	new_hibe_data->is_rust_vector = 1;
	new_hibe_data->vector_size = vector_size;
	new_hibe_data->vector_capacity = vector_capacity;
	new_hibe_data->private_key = new_epoch_pvt_key;
	new_hibe_data->setup_keys = hibe_data->setup_keys;


	return new_hibe_data;
}
// Assuming that the initial epoch is 0
HIBETree *new_hibe_tree(void *hibe_data, int hibe_depth, int max_epoch_depth) {
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
	tree->hibe_depth = hibe_depth;
	tree->max_depth = max_epoch_depth;
	tree->current_epoch = 0;
	// tree->identifiers = {};

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
	//return -10;

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

		//return -20;
		//if (tree->current_epoch >= 1)
		//	return -20;

		n->hibe_data = derive_epoch_hibe(tree, parent, 1);
		if (tree->current_epoch >= 1)
			return -20;
		//return -30;
		parent->left = n;
		//return -40;
	} else if (parent->right == NULL) {
		//TODO: Implement this
		n->hibe_data = derive_epoch_hibe(tree, parent, 0);
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
