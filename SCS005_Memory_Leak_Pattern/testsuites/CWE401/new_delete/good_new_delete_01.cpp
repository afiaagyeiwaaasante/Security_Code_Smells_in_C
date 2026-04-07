/* CWE-401 Memory Leak — good (new with delete)
 * FIX: every allocation via new is paired with delete before the
 *      pointer goes out of scope.
 */

class Node {
public:
    int val;
    Node() : val(0) {}
};

void good_new_delete(int n)
{
    Node *node = new Node();
    node->val = n;
    delete node;  /* FIX: paired delete */
}
