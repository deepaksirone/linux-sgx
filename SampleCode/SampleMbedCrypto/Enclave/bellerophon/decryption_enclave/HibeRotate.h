#ifndef _HIBE_ROTATE_H_
#define _HIBE_ROTATE_H_

#include <vector>

// Binary Tree for minor rotations
// The path from the root to the leaf determines the suffix of the public key

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
	int current_epoch;

	std::vector<int> identifiers;
} HIBETree;

#endif
