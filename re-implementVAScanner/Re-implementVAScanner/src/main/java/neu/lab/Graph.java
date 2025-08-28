package neu.lab;

import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.traverse.DepthFirstIterator;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class Graph {
    public DefaultDirectedGraph<String, DefaultEdge> graph = new DefaultDirectedGraph<>(DefaultEdge.class);

    /**
     * 新增节点和边
     *
     * @param source
     * @param target
     */
    public void addEdge(String source, String target) {
        graph.addVertex(source);
        graph.addVertex(target);
        graph.addEdge(source, target);
    }

    public Set<String> traverse(Set<String> starts) {
        if (starts.isEmpty()) return starts;
        Set<String> methods = new HashSet<>();
        Set<String> collect = starts.stream().filter(start -> graph.vertexSet().contains(start)).collect(Collectors.toSet());
        for (DepthFirstIterator<String, DefaultEdge> it = new DepthFirstIterator<>(graph, collect); it.hasNext(); ) {
            methods.add(it.next());
        }
        return methods;
    }
}
