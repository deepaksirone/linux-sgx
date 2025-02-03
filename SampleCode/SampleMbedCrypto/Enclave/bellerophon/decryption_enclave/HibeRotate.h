#ifndef _HIBE_ROTATE_H_
#define _HIBE_ROTATE_H_

#include <vector>

// Binary Tree for minor rotations
// The path from the root to the leaf determines the suffix of the public key

typedef struct hibe_data {
	int depth;
	int is_rust_vector;
	int vector_size;
	int vector_capacity;
	char *private_key;
	char *setup_keys;
} hibe_data_t;

typedef struct hibe_tree_node {
	bool is_deleted;
	bool is_root;
	int depth;
	int epoch_number;

	void *hibe_data;
	struct hibe_tree_node *parent;

	struct hibe_tree_node *left;
	struct hibe_tree_node *right;
} HIBENode;

typedef struct hibe_tree {
	HIBENode *root;
	HIBENode *current_node;

	int max_depth;
	int hibe_depth;
	int current_epoch;

	//std::vector<int> identifiers;
} HIBETree;

HIBETree *new_hibe_tree(void *hibe_data, int hibe_depth, int max_epoch_depth);
int compute_next_epoch(HIBETree *tree); 

#endif
