/* CWE-401 Memory Leak — C++ new without delete
 * FLAW: object allocated with new but delete is never called before
 *       the pointer goes out of scope.
 */

class Node {
public:
    int val;
    Node() : val(0) {}
};

void bad_new_no_delete(int n)
{
    Node *node = new Node();
    node->val = n;
    /* FLAW: node is never deleted */
}
